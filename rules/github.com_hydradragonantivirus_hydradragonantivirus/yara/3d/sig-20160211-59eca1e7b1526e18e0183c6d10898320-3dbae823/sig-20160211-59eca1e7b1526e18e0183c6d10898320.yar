rule sig_20160211_59eca1e7b1526e18e0183c6d10898320 {
  meta:
    description = "datamaliciousorder - file 20160211_59eca1e7b1526e18e0183c6d10898320.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4efb1453bc4d1c9df0267c881b5959663f0abe338239a101678bf7c255fc7f08"

  strings:
    $s1 = "    while (techniqueMile[('finish', 'manager', 'rcombination'.g()) + 'ea' + ('paradox', 'dflag'.g()) + 'y' + ('trajectory', 'sdi" ascii
    $s2 = "devil', 'base', 'actor', 'positive', 'nreal'.g()) + '']();" fullword ascii
    $s3 = "curacy', 'reservation', '/hall'.g()) + '0' + ('specification', 'show', 'culture', 'antenna', 'analogy', 'vocal', '9authority'.g(" ascii
    $s4 = "formal', 'presumption', 'directive', 'forum', 'salmanac'.g()) + 'e']();" fullword ascii
    $s5 = "ration', 'nzone'.g()) + 'd']();" fullword ascii
    $s6 = "association', 'reputation', '%auction'.g()) + '/') + \"GQo3xa5v\"+('contact', '.sport'.g()) + 's' + ('delegate', 'arena', 'campu" ascii
    $s7 = "    while (techniqueMile[('finish', 'manager', 'rcombination'.g()) + 'ea' + ('paradox', 'dflag'.g()) + 'y' + ('trajectory', 'sdi" ascii
    $s8 = "    function String.prototype.g () {return this.charAt(((700/25)-(28&30)));} " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}