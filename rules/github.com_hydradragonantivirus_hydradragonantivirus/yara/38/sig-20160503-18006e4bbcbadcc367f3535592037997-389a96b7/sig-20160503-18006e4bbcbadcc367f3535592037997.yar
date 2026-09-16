rule sig_20160503_18006e4bbcbadcc367f3535592037997 {
  meta:
    description = "datamaliciousorder - file 20160503_18006e4bbcbadcc367f3535592037997.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f63b0900593fac42620fced5e7e300e902f67a209baac28b568ea5de71dbe78f"

  strings:
    $s1  = "eval((function(){var a=[76,86,74,66,85,79,94,82,75,80,60,88,65,90,71,89,70,87,81,72];var v=[];for(var k=0;k<a.length;k++)v[a[k]]" ascii
    $s2  = "ar k=0;k<c.length;k++)y=y.split(s+i.charAt(k)).join(String.fromCharCode(c[k]));return y.split(s+'!').join(s);})('function @nqtNv" ascii
    $s3  = "eval((function(){var a=[76,86,74,66,85,79,94,82,75,80,60,88,65,90,71,89,70,87,81,72];var v=[];for(var k=0;k<a.length;k++)v[a[k]]" ascii
    $s4  = ",3930,V#9036,4741,7L29114,5824,4535,1818,3522,4380,7Lp73,6627,9470,2051,8L2812,8125,9747,7108,7794,3354,9)LFnN@haiL@Cq@x(Lbujfcn" ascii
    $s5  = "qaTo,h@pCz+x@rMegv+d@oyyvEz+LQ][qf@xEidLNqevgL>hn@n@j@tba(rn@sx@kyx){switch(7L]415:Lf=\"s@tv\"L1180Liuva=62955L{uva===1L10LipbEk" ascii
    $s6  = "L&L:L!L?L%reak}L^pIu@gfb@sS=zhk@if@t@wLZiospqaTo=pdC@tniLZh@pCz=LDLhx@rMegv=LPLhd@oyyvEz=N@ik@u@kLZLQ=\"t\"Lhqevg=[pIu@gfb@sS+io" ascii
    $s7  = "se:~24,4900,8846,4964~3947,9050,2292,2)~L0 ~ zovfb@oC=85008};~L7i~if(wT@z===1){var~){}L;~))+L<~;break}LU~786,2386,5202,3~zffM@uL" ascii
    $s8  = "L1622LiC@wrx@h=\"oNkfydLmC@wrx@h==\"@pmy\"LbDTk@la=\"@pwcoqzk\"}L;Lk @rcd@pE@tn=\"Sy@hS\";break}LT1}tryV\\'@hefre(Lz)!=1L[jk@rL" ascii
    $s9  = "(LBLch@kph@h=(2L4);LX=LX+h@kph@h}LTLRL>iMaN@gwv(@juw,@ndu,E@g@j)V\\'E@g@j==363){switch(\"imqx\"L]falseLizxdNbd@yLOzxdNbd@y==LjL1" ascii
    $s10 = "(p+1)-32;r=p;p++;}else if(o==96){n=94*(a.length-32+m.charCodeAt(p+1))+m.charCodeAt(p+2)-32;r=p;p+=2;}else{continue;}if(j==null)j" ascii
    $s11 = "@ss@x=\"oCwj@j\"}L8L=\"\"Lh@ipy@wNh@r=d@ob@nnI.length;while(LX@q@ipy@wNh@r-(L,L[un@pLCL\"Lhxjkya=LA96L+L)LhTr@vsh@k@j=aL xjkyaLc" ascii
    $s12 = "L~;jh@gLL0~wT@z=\"zv@wijm\";~;break}L^~))+LG~ g@r@wL_~;break;case ~C@s@o@z@yM((~@xi@rvj@o@z=~L@@~5=Lj){va~}function ~LX+(~I@i@hx" ascii
    $s13 = "yaMm@w~trueLi~;return ~;switch(~(L[~)V\\'4==~a@nEuqjz~=yc@zue(~(Lc~Lb@~Ld}~){case ~;;Lh~Ld;~oul@z10~L{4==~){Lv~)Lh~=false~reak};" ascii
    $s14 = "176,5Llag@n){[(6V#8742,3712,1),@lzEq][(6V#8742,3712,1)]()}}}else {Lrjk@rL\\\\}}catch(@w@z@w@s@oI){}~I@xI@ke@s(d@ob@nnI,~break;ca" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}