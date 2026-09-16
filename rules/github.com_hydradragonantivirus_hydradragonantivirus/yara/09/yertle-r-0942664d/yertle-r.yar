rule yertle_r {
  meta:
    description = "yertle - file yertle-r.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-28"
    hash1       = "527d3b0ede0780c48098c4bd43c266ca91c6bd417c7144ef898fa1326292130b"

  strings:
    $s1  = "$shell = 'uname -a; w; id; python -c \\'import pty;pty.spawn(\"/bin/bash\")\\'';" fullword ascii
    $s2  = "// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck." fullword ascii
    $s3  = "Description: This spawns a backdoor PHP reverse shell designed to be used with the Yertle script from WPForce." fullword ascii
    $s4  = "// This script will make an outbound TCP connection to a hardcoded IP and port." fullword ascii
    $s5  = "printit(\"ERROR: Shell process terminated\");" fullword ascii
    $s6  = "// php-reverse-shell - A Reverse Shell implementation in PHP" fullword ascii
    $s7  = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
    $s8  = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii
    $s9  = "// Spawn shell process" fullword ascii
    $s10 = "// The recipient will be given a shell running as the current user (apache normally)." fullword ascii
    $s11 = "Author URI: https://github.com/n00py" fullword ascii
    $s12 = "printit(\"ERROR: Shell connection terminated\");" fullword ascii
    $s13 = "// Make the current process a session leader" fullword ascii
    $s14 = "// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows." fullword ascii
    $s15 = "0 => array(\"pipe\", \"r\"),  // stdin is a pipe that the child will read from" fullword ascii
    $s16 = "// This tool may be used for legal purposes only.  Users take full responsibility" fullword ascii
    $s17 = "Plugin URI: https://github.com/n00py" fullword ascii
    $s18 = "Plugin Name: Yertle Reverse Shell" fullword ascii
    $s19 = "// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available." fullword ascii
    $s20 = "printit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\");" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (8 of them)
    ) or (all of them)
}