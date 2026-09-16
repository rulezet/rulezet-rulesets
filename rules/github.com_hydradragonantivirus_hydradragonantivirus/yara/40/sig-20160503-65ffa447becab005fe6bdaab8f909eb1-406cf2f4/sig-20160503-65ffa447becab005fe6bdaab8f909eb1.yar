rule sig_20160503_65ffa447becab005fe6bdaab8f909eb1 {
  meta:
    description = "datamaliciousorder - file 20160503_65ffa447becab005fe6bdaab8f909eb1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b423e6afd2552929cc9cb4d429b7ec4b0a19f9aa4f766d403eec637bb456a9e0"

  strings:
    $s1  = "eval((function(){var a=[89,71,79,87,70,88,75,85,60,72,94,65,81,66,76,80,90,82,74,86];var x=[];for(var c=0;c<a.length;c++)x[a[c]]" ascii
    $s2  = "ar c=0;c<w.length;c++)s=s.split(t+e.charAt(c)).join(String.fromCharCode(w[c]));return s.split(t+'!').join(t);})('function @gfCwI" ascii
    $s3  = "eval((function(){var a=[89,71,79,87,70,88,75,85,60,72,94,65,81,66,76,80,90,82,74,86];var x=[];for(var c=0;c<a.length;c++)x[a[c]]" ascii
    $s4  = "29,2112,~v@tl@p@m(~]YY~@lz@v@gIS~@ip@mtMv(~=Ya+~uwve@jE()~==1Yd~E@h@iMvea~break};;;~Ipfya@hv=~;break};~Y^@~;return ~==Yq){~;swit" ascii
    $s5  = "(gxwl@n,@p@i@l@j){switch(YzY\\'b@m@gem@iN=60647Y?1:Yoc@rug@sl@n=67021Y\"Yowpv=\"kx@rjCM@l\"Y\"if(@p@i@l@j===446Yd@xTxM=Yq}YWif(@" ascii
    $s6  = "Yg YV\"\"Ylvuio@ll=e@u@n.length;while(Ya@ovuio@ll-(Y,Yd@rNo=YEY#Y!YcgEbYQ(6YLY*YcivyabN=Y:@gEb)Ycvw@r@z=YyY-+(Y,)Yct@tqb@l@mkl=Y" ascii
    $s7  = "(k+1)-32;v=k;k++;}else if(z==96){f=94*(a.length-32+l.charCodeAt(k+1))+l.charCodeAt(k+2)-32;v=k;k+=2;}else{continue;}if(p==null)p" ascii
    $s8  = "@rMS@z@x~;break;case ~bo@xl@kSc\"){~YD@~r gz@zN=fal~[YG~}function ~(598,4018,~owz=28618;~fapr@pa(\"0~\"YY~)+eu@ht((~)YY~witch(tr" ascii
    $s9  = "~Y#3~3,7533,4845,5379,0)~Y?false:~7656,2861,4951,421~125:vaYBs~seYpgz@zN==\"@wN@~@v@m@rgNn=\"kq@yp\";~eY_true:var ~break;case 12" ascii
    $s10 = "}~Y7e~eak;case 300:var~956Yps@yejy==~Y<9~=\"@iD@scvcI\";br~e:YoDc@p=true~))+@YM(~Yyron(e@u@n,~9,3296,8782,3)~Yls@yejy=55~xksYC~Y" ascii
    $s11 = "a~Ie\"){}YWvar~9287,6267,8269,1)~uE@sepYC~6303,9075,3464,2)~ron(e@u@n,Ya~}Y[2){case ~ @y@xv@xYf;if~Y4 ~Yo@rsIvf=44048;~(@y@xv@xY" ascii
    $s12 = "5,1),@xfxk@xT][(335Yx50,4343G*6,4350Y}5,9590,7956,6491,2637,6116,7845,1)]()}}else {YonkvfSDY`}else {YonkvfSDY`}catch(@tk@hg@w){}" ascii
    $s13 = "ch(~7039,622~(Yd~(Ye~){case ~Yf}~@nm@kok~@slqwCt~Yl@~){Yo~)Yl~=Yze~;;;var~@kqcb@~mmoo@z~m@ko10~@y@z@v~;Yo~vw@sM~)Yp~var ~;if(~tr" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}