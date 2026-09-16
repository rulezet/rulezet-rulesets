rule sig_20160517_22b97271cca95dc886d05490ff363577 {
  meta:
    description = "datamaliciousorder - file 20160517_22b97271cca95dc886d05490ff363577.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "898cee90630f23ac165325a6884aa976917f00747bab253dcabe3eecb444cf44"

  strings:
    $s1 = "var zgalti='vr3f1aathaihrjtfau bincnjm1dd1blynnikrsltsonj4uvymmpurasca2iul4iygdsje11=njtcd\\'owqpqtzbdbzcpqb4rneuu1tihjdjjfebx2i" ascii
    $s2 = "i=r4+\"v\"+\"al\";   WScript.lister=5;   l3n1hwxwii=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+\"ng\"+\"th\"]) " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}