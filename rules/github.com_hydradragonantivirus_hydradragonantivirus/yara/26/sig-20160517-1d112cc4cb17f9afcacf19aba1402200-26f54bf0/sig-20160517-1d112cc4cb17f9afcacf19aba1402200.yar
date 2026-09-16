rule sig_20160517_1d112cc4cb17f9afcacf19aba1402200 {
  meta:
    description = "datamaliciousorder - file 20160517_1d112cc4cb17f9afcacf19aba1402200.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44e66b45d7a4f5f340afe1146ce63029a25ca1430897287270f29e534d2388a3"

  strings:
    $s1 = "var yip='valwdmajchksryqszs ffmrmet4slbog24qfcjnu4veua2sovc4fm3yylhocjnvgqh3sjipaeowrmzptxaoq=wit3z\\'sakettacp3xcnohidnca4drihu" ascii
    $s2 = "xp\");   z1ogvuvdmq=r4+\"v\"+\"al\";   WScript.lister=5;   z1ogvuvdmq=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}