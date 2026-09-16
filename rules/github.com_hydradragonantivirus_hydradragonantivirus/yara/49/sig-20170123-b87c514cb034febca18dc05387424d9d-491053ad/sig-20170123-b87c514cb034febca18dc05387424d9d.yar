rule sig_20170123_b87c514cb034febca18dc05387424d9d {
  meta:
    description = "datamaliciousorder - file 20170123_b87c514cb034febca18dc05387424d9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed7693765fc4da79640ed3d0e16f723445843117d177b595e4b0bcdbb3152786"

  strings:
    $s1 = "//if ([\"exdiwce\", \"pgop\", \"mpojqyjqa\", \"rypbewc\", \"urop\", \"zyzs\", \"rfyf\", \"bocyve\", \"inamciv\", \"ofokko\", \"e" ascii
    $s2 = "onoczad3 = this[[\"aswu\", \"ihmaq\", \"ciqby\", \"gokzara\", \"avixlol\", \"uxuti\", \"pirurr\", \"rapnixca\", \"astatadg\", \"" ascii
    $s3 = " Function([\"yqzuw\", \"myhh\", \"ywtu\", \"fribote\", \"uqne\", \"ury\", \"llejyz\", \"yqtegw\", \"vynloz\", \"ihny\", \"kkuz\"" ascii
    $s4 = "onoczad3 = this[[\"aswu\", \"ihmaq\", \"ciqby\", \"gokzara\", \"avixlol\", \"uxuti\", \"pirurr\", \"rapnixca\", \"astatadg\", \"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}