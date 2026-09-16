rule sig_20160517_b5d7685de38470787722de57b203b735 {
  meta:
    description = "datamaliciousorder - file 20160517_b5d7685de38470787722de57b203b735.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4db44c879c72bc0795d3ef2be83c0b1ae47efde31fc6c435f6833f4d719dba47"

  strings:
    $s1 = "var khd='vgioooafufqzri31hp tltbpuyays2cqbi13ydrldfgdlajcnypea1fekmrqrwjuab1m4he4=exuzb\\'x3rfmtgjcboct43tvnnyfn3iijbwsfwgqafuzf" ascii
    $s2 = "4+\"v\"+\"al\";   WScript.lister=5;   fczxqu1cm=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  {  " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}