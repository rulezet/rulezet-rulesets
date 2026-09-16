rule sig_20160503_8ca7841ef7c1ccfa45834a3bb53b93c0 {
  meta:
    description = "datamaliciousorder - file 20160503_8ca7841ef7c1ccfa45834a3bb53b93c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "008a13b59391e8ae094d241c8c974107311903b3414f5723161d6969a658baeb"

  strings:
    $s1  = "eval((function(){var z=[66,60,90,65,89,85,94,88,81,82,72,76,87,86,80,79,75,71,70,74];var a=[];for(var n=0;n<z.length;n++)a[z[n]]" ascii
    $s2  = "ar n=0;n<r.length;n++)e=e.split(o+l.charAt(n)).join(String.fromCharCode(r[n]));return e.split(o+'!').join(o);})('function C@k<%C" ascii
    $s3  = "(j+1)-32;d=j;j++;}else if(p==96){t=94*(z.length-32+i.charCodeAt(j+1))+i.charCodeAt(j+2)-32;d=j;j+=2;}else{continue;}if(y==null)y" ascii
    $s4  = "eval((function(){var z=[66,60,90,65,89,85,94,88,81,82,72,76,87,86,80,79,75,71,70,74];var a=[];for(var n=0;n<z.length;n++)a[z[n]]" ascii
    $s5  = "@wa=BU+(68B,B+;BGB!gsM@sq@wa)};Bf=x@kb(\"\"+@r@jlf@s@q+\"\"BauN@wId@oI=jo@iy(BL< Cqngio@q@q=iyM@z@l(@uN@wId@oI,T@i@u@vBaqzmpN@kw" ascii
    $s6  = ";;Bn~BC4~415,5883,6438~m@yBN~r @xN@kDl=\"S@~B\\\\ase \"~,9924,6656,3)~;break}Bn~BH,~,2707,1735,1~BU+(2~BM@~))BY~@r@jlf@s@q=~9,54" ascii
    $s7  = "771B7459Bo@vc@wyNzu=\"wupx@z@k@iBp@vc@wyNzu===0BkSk@nr=45775};B:BG\"\"Bnw@s@xS=p@z@pt@xw.length;while(BU@hw@s@xS-(68B,B+Bks@tu@g" ascii
    $s8  = "030~nE@jt@kvw()~e@z@nd@s@vv~@qzmpN@kw10~BU);~}function ~[BT~))+Bg~jSTxxt@p()~\"BZ~Br;if(~)BZ~dj@l@p(\"0~S@gpSEqvI~};Bb~=(4707,85" ascii
    $s9  = "=42170;Bt};~EB6s~se \"bpd@y@kyl\":v~eak;case 0Bo~ m@ulMa=17444;i~@xN@kDl=\"S@iEb~b@ju\"B\\\\a~}B\\\\ase ~@i@wp@y@v@s()~ase B|:va" ascii
    $s10 = "B]~+@r@g@v((~;return ~=Br){~;Bt;c~8700,890~(Bk~()Bn~){case ~)Bn@~switch(~=B|;~\"Bk~Br};~@pMd@xi~wy@wn((~B|){~=xh@ih(~S@qco@x~){<" ascii
    $s11 = "}}catch(xjdf@y){}~reak;case trueBo~zg@xNSTq(p@z@pt@xw,~13,778,4854,5073,0)~feo@uBcbreak};~witch(1B`0:var~f(m@ulMa==677){};br~B)7" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}