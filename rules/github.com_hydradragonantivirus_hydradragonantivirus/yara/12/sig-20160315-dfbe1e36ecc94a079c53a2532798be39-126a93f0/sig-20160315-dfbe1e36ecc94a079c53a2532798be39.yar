rule sig_20160315_dfbe1e36ecc94a079c53a2532798be39 {
  meta:
    description = "datamaliciousorder - file 20160315_dfbe1e36ecc94a079c53a2532798be39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a6c57b3a19c424e4211f414cdf81235e1acf99224a22d8c02dcc2e3775d2672"

  strings:
    $s1  = "    KUUBOYD = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      " ascii
    $s2  = "swerve = tkyoMmlx[3 * 5 - 3 * 3].split(\"trucks\").join(\"\");" fullword ascii
    $s3  = "    QjVSMd.open((\"stenographer\",\"annunciation\",\"G\")+\"ET\", (\"exaggerate\",\"addicted\",\"h\")+\"tt\"+\"p:\"+(\"council\"" ascii
    $s4  = "aviest\",\"og\")+\"s/\"+(\"emetic\",\"marked\",\"87\")+\"yg\"+(\"senile\",\"enlightenment\",\"marine\",\"756f\")+\"5.exe\", fals" ascii
    $s5  = "QjVSMd.onreadystatechange = function () {" fullword ascii
    $s6  = "h[5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s7  = "chalice = ((\"universality\", \"conducive\", \"zNIPYIBNhd\", \"similarly\", \"pilEwPpqwWFn\") + \"dPvhWih\").rocky();" fullword ascii
    $s8  = "    (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s9  = "String.prototype.rocky = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "        voLGtdWkxx = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s11 = "et excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesis " ascii
    $s12 = "zzle.error( match[0] );     \";" fullword ascii
    $s13 = ")+(\"madhouse\",\"whosoever\",\"injuries\",\"ucks\")+(\"hosea\",\"situations\",\"matched\",\"distinct\",\"iv\")+(\"constraint\"," ascii
    $s14 = "pt\"+(\"caption\",\"bathroom\",\"sophisticated\",\"cabriolet\",\"tr\")+(\"synonym\",\"adams\",\"uc\")+\"ks.\" + (\"marina\",\"tr" ascii
    $s15 = "thodoxy\",\"damaging\",\"truc\")+(\"pegasus\",\"spaces\",\"ksje\")+(\"bygone\",\"dickie\",\"tr\")+(\"nonexistent\",\"manna\",\"u" ascii
    $s16 = "hGYUSwIij = \" filter: {\";" fullword ascii
    $s17 = "var tnHNPSpaH = this[swerve];" fullword ascii
    $s18 = " 0/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) ); " ascii
    $s19 = "zSzAlDirc = \"  \\\"CHILD\\\": function( match ) {    /* matches from matchExpr[\\\"CHILD\\\"]     1 type (only|nth|...)     2 w" ascii
    $s20 = "        voLGtdWkxx = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii

  condition:
    uint16(0) == 0x5441 and
    8 of them
}