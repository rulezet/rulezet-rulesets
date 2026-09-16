rule yertle_yertle {
  meta:
    description = "yertle - file yertle.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-28"
    hash1       = "2031cea1ee6be78abc632b7be0b4ef3c180da44d601348543db408b68b0ec4d6"

  strings:
    $s1  = "// Copied and modified from https://github.com/leonjza/wordpress-shell" fullword ascii
    $s2  = "Author URI: https://github.com/n00py" fullword ascii
    $s3  = "Description: This is a backdoor PHP shell designed to be used with the Yertle script from WPForce." fullword ascii
    $s4  = "Plugin URI: https://github.com/n00py" fullword ascii
    $s5  = "$command = substr($command, 0, -1);" fullword ascii
    $s6  = "Plugin Name: Yertle Interactive Shell" fullword ascii
    $s7  = "call_user_func_array('system', array($command));" fullword ascii
    $s8  = "$command = base64_decode($command);" fullword ascii
    $s9  = "call_user_func('system', $command);" fullword ascii
    $s10 = "$command = $_GET[\"cmd\"];" fullword ascii
    $s11 = "system($command);" fullword ascii
    $s12 = "$thingy = $function->invoke($command );" fullword ascii
    $s13 = "$function = new ReflectionFunction('system');" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (8 of them)
    ) or (all of them)
}