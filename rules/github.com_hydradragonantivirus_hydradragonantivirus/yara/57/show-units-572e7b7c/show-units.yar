rule show_units {
  meta:
    description = "amadey-botnet - file show_units.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "07905fbf257cacc7a9dd47381c9435f3366a472e3e6db998154a4e50c94223ed"

  strings:
    $s1  = "echo \"SQL connection filed, check host, name, login and password\";" fullword ascii
    $s2  = "<td><div align = center> <a href=\\\"show_units.php?sort=version\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show" fullword ascii
    $s3  = "echo \"&nbsp;<img src=\\\"images\\ic_11.png\\\"> \" . date( \"s\", ( time() - $row['online'] ) ) . \" sec\" ; " fullword ascii
    $s4  = "<td><div align = center> <a href=\\\"show_units.php?sort=ip\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"] . " fullword ascii
    $s5  = "<td><div align = center> <a href=\\\"show_units.php?sort=arch\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"] " fullword ascii
    $s6  = "<td><div align = center> <a href=\\\"show_units.php?sort=id\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"] . " fullword ascii
    $s7  = "<td><div align = center> <a href=\\\"show_units.php?sort=os\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"] . " fullword ascii
    $s8  = "<td><div align = center> <a href=\\\"show_units.php?sort=ar\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"] . " fullword ascii
    $s9  = "<td><div align = center> <a href=\\\"show_units.php?sort=online\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"" fullword ascii
    $s10 = "<td><div align = center> <a href=\\\"show_units.php?sort=reg\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show\"] ." fullword ascii
    $s11 = "$result = mysql_query( \"SELECT * FROM units WHERE online > \" . ( time() - 60 ) . \" ORDER BY $J DESC LIMIT $f, 100\" );" fullword ascii
    $s12 = "echo \"<td><div align = center> <a href=\\\"show_units.php?sort=pc\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"" fullword ascii
    $s13 = "echo \"<td><div align = center> <a href=\\\"show_units.php?sort=av\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"" fullword ascii
    $s14 = "echo \"<td><div align = center> <a href=\\\"show_units.php?sort=un\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"" fullword ascii
    $s15 = "<td><div align = center> <a href=\\\"show_units.php?sort=country\" . \"&f=\" . $_GET[\"f\"] . \"&show=\" . $_GET[\"show" fullword ascii
    $s16 = "<td bgcolor = \" . $gb . \"><div align = left>\" . \"&nbsp;<img src=\\\"images\\ic_6.png\\\"> \" . $row['version'] . \"</div" fullword ascii
    $s17 = "header( \"Location: login.php\" );" fullword ascii
    $s18 = "if ( @mysql_connect( $conf['dbhost'], $conf['dbuser'], $conf['dbpass'] ) == false )" fullword ascii
    $s19 = "$all = mysql_query( \"SELECT * FROM units WHERE online > \" . ( time() - 60 ) );" fullword ascii
    $s20 = "<td bgcolor = \" . $gb . \"><div align = left>\" . \"&nbsp;<img src=\\\"images\\ic_8.png\\\"> \" . $row['os'] . \"</div></td" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (8 of them)
    ) or (all of them)
}