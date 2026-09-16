rule sig_20160516_6becb919af531d2db13d2592ea4f7d43 {
  meta:
    description = "datamaliciousorder - file 20160516_6becb919af531d2db13d2592ea4f7d43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d11102e63e0ab78a71362530c8272ec005fa4827bf4e6ffdbd07b5933f6e34ce"

  strings:
    $s1 = "var wxwdab='vmk3stanqrlhrijiy2 hdosgfp3y4wxqv3asja1css2vcjsr3fdaccpumjvejh4hsdawg4gkjg1k3s=r4yqv\\'ik4urto1dsvcgnzyfndcpgniicnof" ascii
    $s2 = "+\"cript\"+\".RegE\"+\"xp\");   lfzdzsjmvw=r4+\"v\"+\"al\";   WScript.lister=5;   lfzdzsjmvw=\"\"+\"s\";   ww=232323;   }catch(x" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}