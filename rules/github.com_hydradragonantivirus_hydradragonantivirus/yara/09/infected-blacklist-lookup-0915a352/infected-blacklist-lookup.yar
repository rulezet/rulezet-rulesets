rule infected_blacklist_lookup {
  meta:
    description = "phishing - file blacklist_lookup.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "921abc8cd5b73ed1f639de236bfa62bf0c6cc3a8a142e403d3e24cd26f110cd4"

  strings:
    $s1  = "** private function that converts single ip address to CIDR format," fullword ascii
    $s2  = "** private function that reads the file into array" fullword ascii
    $s3  = "**      example '_whitelist.dat' and '_blacklist.dat' files for the" fullword ascii
    $s4  = "** looseits. The commented lines will be used for future" fullword ascii
    $s5  = "**      default to '_whitelist.dat' and '_blacklist.dat'.  If either" fullword ascii
    $s6  = "** converts an IP address to an array of two long integer," fullword ascii
    $s7  = "return (($this->compare($dip,$dlow) != -1) && ($this->compare($dip,$dhigh) != 1)); " fullword ascii
    $s8  = "public function __construct( $whitelistfile = 'includes/whitelist.dat', " fullword ascii
    $s9  = "private $statusid = array( 'negative' => -1, 'neutral' => 0, 'positive' => 1 );" fullword ascii
    $s10 = "return file_put_contents( $this->ipfile, $ip, $comment ); " fullword ascii
    $s11 = "** due to the integer size restrictions of platforms, we" fullword ascii
    $s12 = "** also removes excess spaces from within the string." fullword ascii
    $s13 = "** public function that returns the ip list array" fullword ascii
    $s14 = "**      boolean ipPass( <ipaddress> )" fullword ascii
    $s15 = "$dnetmask = ~(pow( 2, ( 32 - $netmask)) - 1);" fullword ascii
    $s16 = "$blacklistfile = 'includes/blacklist.dat' ) {" fullword ascii
    $s17 = "throw new Exception( $fname.': '.$e->getmessage() . '\\n');" fullword ascii
    $s18 = "// Created by legzy -- icq: 692561824 " fullword ascii
    $s19 = "**      If whitelist and blacklist filenames are not provided, they will" fullword ascii
    $s20 = "**  class IpBlockList( <whitelistfile>, <blacklistfile> );" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (8 of them)
    ) or (all of them)
}