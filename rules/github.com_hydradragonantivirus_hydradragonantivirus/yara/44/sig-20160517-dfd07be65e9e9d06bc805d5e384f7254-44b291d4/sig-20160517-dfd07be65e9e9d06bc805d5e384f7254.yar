rule sig_20160517_dfd07be65e9e9d06bc805d5e384f7254 {
  meta:
    description = "datamaliciousorder - file 20160517_dfd07be65e9e9d06bc805d5e384f7254.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "855d558b31db8278ebde788a7be3586308a4659f6282a91782c466bb31daeeba"

  strings:
    $s1 = "var zt1o='vizp2yalhcqxrmvj2u yxrxueizzbratxafxbwsxhuydsc3i4cldmmyi1ktyfrryfxttpuuztnnrpz=dlrsn\\'rv3hitkjjaccwjygtnk1iqvikji43fe" ascii
    $s2 = "xp\");   jsr2fhyvl=r4+\"v\"+\"al\";   WScript.lister=5;   jsr2fhyvl=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}