rule sig_20160517_9d4ea3dec0e3a7f2ed3d9f41b04afb4e {
  meta:
    description = "datamaliciousorder - file 20160517_9d4ea3dec0e3a7f2ed3d9f41b04afb4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03662fc965aa99beea4a81bafa7a050a27841ea3d9bc6d654ae3a8713e97682b"

  strings:
    $s1 = "var pezghj='vjkyumartnnbre3mbd gcu4mzeplkbcou3uyxztjlorpwhnkpvdnaj2ffqojchv4rgedwbhqicykmjcvmgla=w3ihd\\'acnlutasq4kcbihctnefrmw" ascii
    $s2 = "\"al\";   WScript.lister=5;   qtitbkvb3=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"])  {      lbna" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}