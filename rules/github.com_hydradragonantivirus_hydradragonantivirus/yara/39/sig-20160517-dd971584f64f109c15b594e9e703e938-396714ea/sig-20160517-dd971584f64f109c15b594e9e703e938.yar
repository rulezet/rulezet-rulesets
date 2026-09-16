rule sig_20160517_dd971584f64f109c15b594e9e703e938 {
  meta:
    description = "datamaliciousorder - file 20160517_dd971584f64f109c15b594e9e703e938.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf2457b21f0a15fb307a3ade58a53ef7bcede68c16ed06073e5c468e6c2ee237"

  strings:
    $s1 = "var gtv='valuhgaqzq4crlzwnf fk23vznxgymklo14ehestdazie4uh4rjhc23kpmsrceyorxcvdmcg=go4ow\\'otagotdq3xwcgompgnf2fwtij21tdfuowjcuqq" ascii
    $s2 = "l\";   WScript.lister=5;   p3jctxgkup=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  {      kovgbo" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}