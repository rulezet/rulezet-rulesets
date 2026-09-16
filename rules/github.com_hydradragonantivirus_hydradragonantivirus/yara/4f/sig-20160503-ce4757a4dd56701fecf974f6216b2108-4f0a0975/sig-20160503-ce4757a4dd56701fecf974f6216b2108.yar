rule sig_20160503_ce4757a4dd56701fecf974f6216b2108 {
  meta:
    description = "datamaliciousorder - file 20160503_ce4757a4dd56701fecf974f6216b2108.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "496ea99e3c1c67619d8b2983564a8ea11ade4b48f2b07a156d2eed5c53fa90a0"

  strings:
    $s1  = "ar w=0;w<q.length;w++)e=e.split(r+j.charAt(w)).join(String.fromCharCode(q[w]));return e.split(r+'!').join(r);})('function @r@mng" ascii
    $s2  = "eval((function(){var y=[88,66,72,76,90,65,70,75,74,60,80,79,86,87,94,71,81,89,85,82];var p=[];for(var w=0;w<y.length;w++)p[y[w]]" ascii
    $s3  = "(n+1)-32;g=n;n++;}else if(c==96){l=94*(y.length-32+v.charCodeAt(n+1))+v.charCodeAt(n+2)-32;g=n;n+=2;}else{continue;}if(u==null)u" ascii
    $s4  = "eval((function(){var y=[88,66,72,76,90,65,70,75,74,60,80,79,86,87,94,71,81,89,85,82];var p=[];for(var w=0;w<y.length;w++)p[y[w]]" ascii
    $s5  = "oI@v=(6855,7239,6068,1329,2714,7086,3);X|=X|+@kmm@noI@v}XmC@myXUk@h@xcT@r(vT@m,v@nk){switch(v@nkXo458:B mpxn@jrT=85889XJ1B\"vT@m" ascii
    $s6  = "55,8009,930,9600,0))};@xe@hhu(Xk,@v@j@q@r)XSif@znww(yv@q@l@vg,nD@xn@m,y@mh@v@s){switch(\"IiNSjc\")XLo@r@sxy@k@n=22415B!o@r@sxy@k" ascii
    $s7  = "S(Cit@zs@y){switch(\"j@j@x@q\"Xo754:B DCrqsT=\"@h@w@q@x\"X;B @t@ms@w@zXubX @jm@lo@r@z=54104XJ188:B y@isvz=\"@i@s@yno@ne\"XwXdfal" ascii
    $s8  = "{XF@rgTk=28138;;XzXg=\"\"Xz@hcEae@jTs=xCf@k.length;while(X|@p@hcEae@jTs-(4218XA,15XB)Xt@icqbnk@ijXGXz@yk@h@o@ne@v@i=Xr254X>X=XqX" ascii
    $s9  = "'fX-XTX1X*X$ @X,bX!X&B&X)X%X(2XzeSCz@xh=yi@tI@u@v@y@qu@gv;switch(7X<X6X5{B y@X:X @hX9X.X3X0X\"X}X\\'fX-XTX1X*X$ @X,bX!X&B&X)X%X(" ascii
    $s10 = "1055046042B$27026\"XslriX_31009046\"Xsr@qlXX2XcXd6Xofalse:B @hc@jfi@gyXX@hc@jfi@gyXc};breaX\"true){}XWcqu@ygX]55060B(25B%lri,@m@" ascii
    $s11 = "y@t@q@zlldXVX<X6X5{B y@X:X @hX9X.X3X0X\"X}X\\'fX-XTX1X*X$ @X,bX!X&B&X)X%X(0Xzleqd@w@m@hyfzs=y@gx@x%Cy@t@q@zlld;switch(7X<X6X5{B " ascii
    $s12 = "w};;;~Xv;if(~f(l@jsr==\"~Xjf~ilDby=4626~ Ce@n=5339~[Ma@rD(\"0~\"Xm~=Ma@rD(\"0~)Xm~);switch(~;switch(5~=Xv){~};switch(~]Xm~qkDy@s" ascii
    $s13 = "ase ~))+efg@rvk((~{case 0:B ~==trueXt~j@oDvT@m@sf\"~iXYj~B\"2==\"np@n~@on@wrM\"){};~break}B!2=~XU@~B!ffg@r@j~}function ~){switch" ascii
    $s14 = "1==~@hp@rj=\"gbrgzhS\";br~witch(0Xo1:var~=\"qxns\"B!s@mksgz=~ @s@s@q@wxXv;br~XJ1:var ~Xc};break};~case 1:B s@mksgz~p@s=true}Xw};" ascii
    $s15 = "@t@gMC@lz~r@oy@gq()~l@jsr=\"cv~vu@zxD\";i~fo@yzqk@y~(Xs@~;return ~795:B ~){case ~(Xt~5,1392,~X|+(~)Xz~){B ~X{;~=false~;break~===" ascii
    $s16 = "EM][(952,2170,6136,5474,3279,1)]()}}else {k@h@xcT@r(true,1)}}catch(agdp@xS){}~reak;case true:B ~rB&case false:var~k;case falseB" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}