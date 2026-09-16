rule sig_20160419_2def53b94658cc32f987e10ec4f5dfed {
  meta:
    description = "datamaliciousorder - file 20160419_2def53b94658cc32f987e10ec4f5dfed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba106546cf540484774ff236a24c13c503d8dddbb3b1cb53c6e640d1dd45501"

  strings:
    $s1  = "return heMOedh[0] + heMOedh[2] + heMOedh[4] + \".F\" + heMOedh[7] + heMOedh[9] + heMOedh[12] + heMOedh[14];" fullword ascii
    $s2  = "var HI = true  , PfDa = FPj[7] + FPj[9] + FPj[11];" fullword ascii
    $s3  = "var FPj = (\"2.XMLHTTP ghHCddo GdIJX XML ream St vZvTnwwU AD MxoamTY O twXl D\").split(\" \");" fullword ascii
    $s4  = "MDJg.open(GVMuU,atkbQ,false);" fullword ascii
    $s5  = "return wTyjklL;" fullword ascii
    $s6  = "nOW = a; break; " fullword ascii
    $s7  = "function zQdI(sZWdf,atkbQ,GVMuU) {" fullword ascii
    $s8  = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s9  = "function omcWHh(tfeYoSS) {" fullword ascii
    $s10 = "if(a>=v.length) {break;}" fullword ascii
    $s11 = "return nVHwt;" fullword ascii
    $s12 = "if (BjqYw != 532-332){return false;} else {return true;}" fullword ascii
    $s13 = "return zwHcTt[mOzd[889-889]]=718-718;" fullword ascii
    $s14 = "function cThmriVQ(MzR) {" fullword ascii
    $s15 = "function SAtcx(zwHcTt) {" fullword ascii
    $s16 = "function IjnN(AFyEc) {" fullword ascii
    $s17 = "function Eiyr(drAym,OIRBC) {" fullword ascii
    $s18 = "function KEAKM(wjF,OXBpJ) {" fullword ascii
    $s19 = "return hVlsHEo[0];" fullword ascii
    $s20 = "if (AFyEc > 198403-451){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}