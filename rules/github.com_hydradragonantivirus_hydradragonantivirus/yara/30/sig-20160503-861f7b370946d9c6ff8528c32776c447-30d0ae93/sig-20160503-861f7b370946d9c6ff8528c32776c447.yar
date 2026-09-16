rule sig_20160503_861f7b370946d9c6ff8528c32776c447 {
  meta:
    description = "datamaliciousorder - file 20160503_861f7b370946d9c6ff8528c32776c447.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd3c13353fae2eb090aa1b6c3afba4dc5e20026207293a7f69bb92cade71a691"

  strings:
    $s1  = "eval((function(){var s=[71,65,81,87,82,72,88,79,80,75,60,85,89,76,90,74,94,86,66,70];var v=[];for(var i=0;i<s.length;i++)v[s[i]]" ascii
    $s2  = "ar i=0;i<l.length;i++)k=k.split(b+w.charAt(i)).join(String.fromCharCode(l[i]));return k.split(b+'!').join(b);})('function dN@s@r" ascii
    $s3  = "alseGY~))+GG~@iE@h@k@m@yEI~=(5985Gy0,3~break};;G]~GC);~)GD~GE@~Dp@uS@t@y@t~)+GJ~}function ~h@ij@hIM()~MMDoy@lq((~\"GL~==1GY~@rt@" ascii
    $s4  = "*)G]tob@kt@k@nG!G@GX=tob@kt@k@n+i@k@l@x@nt+vqE@minG]kakwG!G@GpmwbG[G]@rt@v@pE@h=\"aj@iou\";;G]Gl2=(q@z@lmCI(fhEb@xid,G9G\\\\G(G&" ascii
    $s5  = "(x+1)-32;y=x;x++;}else if(q==96){e=94*(s.length-32+p.charCodeAt(x+1))+p.charCodeAt(x+2)-32;y=x;x+=2;}else{continue;}if(a==null)a" ascii
    $s6  = "v){switch(\"j@ko@g\"GTGb:G^ovI@x@v=\"McSetqw\";bG,g@z@hjyGZG?b@u@gCs=fabe(mgNMEI@v)GLb@u@gCsGEMMDoy@lq(@g@tejI@r@o@sGYk@v@kes@g@" ascii
    $s7  = "@xid.length;while(GC@qI@g@ja@ySI-(3793,315G-G*GYlbrxe@o@jG>G G]tl@xl@mx@my=G9G\\\\G(G&G]i@k@l@x@ntG!tl@xl@mx@my)G]vqE@minG!G9GVG" ascii
    $s8  = ";GC=GC+w@ux@mq@xlx}GLGKGEEyf@hcb(xws@mq@n,@t@x@y@lo@x,sgz){switch(1GTtrue:if(sgz===0GYd@mb@n@k=50449}G8if(sgz=G_GY@x@rrG[}GNG^km" ascii
    $s9  = "28Gz53046G}37Gm7062G}12018034033\")G]lhc=Gnr@yyh@mwGaGWG218Gr08002A 35\")]==(339Gv33,200)){switch(0GT\"@rMt\":if(2==\"j@hpp@z@n@" ascii
    $s10 = "eval((function(){var s=[71,65,81,87,82,72,88,79,80,75,60,85,89,76,90,74,94,86,66,70];var v=[];for(var i=0;i<s.length;i++)v[s[i]]" ascii
    $s11 = "g@vi@p=\"@yM@vzk\";bG,@ri@x@uCs@l=\"@hwzzm\";Gk;case \"@sk@oI@m\":if(5==G_){};brG0r gf@o=\"N@gnrTTo\"GNGpsE@ri@o=\"ch@jn@mEk\";;" ascii
    $s12 = "\"qja@u@pg@z\";Gk;case 1:if(2=GI@y@x@vjbwGUbrG0r h@tcn=\"@jzn@h@gGch@tcnGI@plxu=66330};G+G^GxxT@x=57058;G?rr@k=G73406001308802A " ascii
    $s13 = "048041040\")G]tx@ou=G706020061\")G]TNtpG_GM6GT1:G^gq@mqxnS=1231Go@gq@mqxnS==G[A!Gk;case 527G`pxm@im@p@l=55488Gopxm@im@p@l===\"@y" ascii
    $s14 = "}}else {Gpa@y@mnp=36494}}catch(e@ghal@n){}~147,14,6634,3907,0)~=q@z@lmCI(fhEb@xid,~G$v~vvnk@z=\"TE@g@ns@o\";~\"@nvb@o\"){}G]w@~G" ascii
    $s15 = "2287,5683,2207,1)~@ooG3~37,6154,7048,6298~G-,~,5150,528,7888,2)~break;case Gb:~reak;case 1G`~2,4306,2858,6747~878,6185,3153,3)~G" ascii
    $s16 = "SI((~lNe@iipvC~;return ~;switch(~;Gk};~GS@~GR@~){if(7==~()G]~(GY~){case ~G_};~793,315~q@pc@jf~gltdN@m~){Gp~G_;~=Gb~101,46~;Gp~Gp" ascii
    $s17 = "58~eak;case true:va~ q@kxo=63427;var~pG3~[G7~G:,~,7894,8895,11,3~ @n@ruS@vGZ~@s@xDC@o@mw(\"0~;Gk;case 0:~GC+(3~6343,8181,5735~==" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}