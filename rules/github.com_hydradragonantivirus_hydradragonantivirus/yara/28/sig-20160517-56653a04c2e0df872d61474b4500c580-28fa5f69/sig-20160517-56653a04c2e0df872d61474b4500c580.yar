rule sig_20160517_56653a04c2e0df872d61474b4500c580 {
  meta:
    description = "datamaliciousorder - file 20160517_56653a04c2e0df872d61474b4500c580.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "659a62bec55f7b235f312ba855068d82b632b988d11cddaac21b40811b3e6a7f"

  strings:
    $s1 = "var khd='vgioooafufqzri31hp tltbpuyays2cqbi13ydrldfgdlajcnypea1fekmrqrwjuab1m4he4=exuzb\\'x3rfmtgjcboct43tvnnyfn3iijbwsfwgqafuzf" ascii
    $s2 = "4+\"v\"+\"al\";   WScript.lister=5;   fczxqu1cm=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  {  " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}