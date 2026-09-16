rule sig_20160321_a6f926829f79b51448a639d5f73ef95b {
  meta:
    description = "datamaliciousorder - file 20160321_a6f926829f79b51448a639d5f73ef95b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8a5bc3fee54ea336667c0f281f2c1c6e90500799f32ceab9aa5e7d3aeb3e01c"

  strings:
    $x1 = "var n96='all',q2='\"); ',c6='si',r77=' *.',m89='); v',g1='ll\");',t82='.W',x35='op (',d43='}; i',f12='s+',e79='); ',a52='es.\")'" ascii
    $s2 = "'v *',a80='\"+ad',x97='Run ',p35='et',c30='eL',j92='cq',d79='ll ',g38='eva',x89='\"open',q10=' = ',k63='/buy_',e80='(\"',u58=' t" ascii
    $s3 = ",e15='cq); ',r24='tch ',m47='; ',f57='n fin',h67='Line',f34='.ra',j77='y ',b82='.cd',q38=' link',f13='in',r47='e(\"',r6='\"To',n" ascii
    $s4 = "z24='T\"',s46='h, u',v71='0; t',o13=' in',f9=' with',x90='Fi',d37='le',g25='(\"RE',h7='a.',z25='rite',f78='ECR',t75='n+\"',s37='" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}