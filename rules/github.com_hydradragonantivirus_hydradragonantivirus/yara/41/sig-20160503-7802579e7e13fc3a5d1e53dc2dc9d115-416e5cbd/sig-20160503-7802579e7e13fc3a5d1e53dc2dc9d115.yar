rule sig_20160503_7802579e7e13fc3a5d1e53dc2dc9d115 {
  meta:
    description = "datamaliciousorder - file 20160503_7802579e7e13fc3a5d1e53dc2dc9d115.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b5a2c636885e4a5a78d8f2f94ff9897db46f589c3ef775445bc1fc7e181e8f8"

  strings:
    $s1  = "ar f=0;f<i.length;f++)j=j.split(g+p.charAt(f)).join(String.fromCharCode(i[f]));return j.split(g+'!').join(g);})('function @kxEdv" ascii
    $s2  = "eval((function(){var q=[88,71,79,81,66,89,60,74,80,94,72,70,90,65,87,75,76,86,82,85];var t=[];for(var f=0;f<q.length;f++)t[q[f]]" ascii
    $s3  = "length;while(XF@m@j@iMz@w-(9209,933X*X,XTD@z@lgx@kX4X\"XajzkX=X(X\\'XaaqDX2jzkXUdIct@x=XYX++(9209,933X*X,XUrvc@nl@yw=XYX+);XD=rv" ascii
    $s4  = "ete)X>kuq@uzw(){switch(XiXQXiXbNba@v@h=\"@u@j@qrmtXdNba@v@h==677){}X)yyI=\"l@rNa@x@ywXdyyI==0X;Xjp@oN@g=57104}try{kuq@uzw(1Xef@z" ascii
    $s5  = "tw=\"@nuw@s\";brX f@kD=\"v@u@q@v\";break}XG0X>pkS(XTC@wwoNg@ni=[(2746,5512,7581,3622,5422,3231,1),@tctive@g@ibject,(761,5831,56X" ascii
    $s6  = "{Xjiy@uktM=\"rXBiy@uktMX>docd(XTyz@sMC@oi=\"CXByz@sMC@oiX:sr@sgo(XTfucoz=\"@tXBfucozX>mX@{switch(2XQ0Xbu@tn@q@wsoXc;brX @ou@rI@r" ascii
    $s7  = "ziXUyM@lgrc=@zlpXPb@k@sk=String;Da@r=Da@r+b@k@sk[yM@lgrc](X<XU@lj@io=(1538,X0;XFX=@lj@io}XGDa@rX>f@zdjSjE(p@s@l@kx){switch(419XQ" ascii
    $s8  = "(d+1)-32;c=d;d++;}else if(n==96){l=94*(q.length-32+a.charCodeAt(d+1))+a.charCodeAt(d+2)-32;c=d;d+=2;}else{continue;}if(o==null)o" ascii
    $s9  = "eval((function(){var q=[88,71,79,81,66,89,60,74,80,94,72,70,90,65,87,75,76,86,82,85];var t=[];for(var f=0;f<q.length;f++)t[q[f]]" ascii
    $s10 = ",16~)+@qd@s@s@i((~}X9~==falseXT~@rovdXH~;break;case ~X>@~){}XK~@q@hhDhf@qn~=XF+~}function ~XW;if(~tp@r@q@v()~)XR(4~\"XG~pot@n@k(" ascii
    $s11 = "SjE(Xi)X7MrD@v@s@yI=34548};if(@kxEdv(0,1,\"e@y@s\",\"Cwps@kCa\")!=1XTMrD@v@s@yI=34548}else {Xjd@l@r=([(3831,2818,4585,7712,4044," ascii
    $s12 = "~qm@v@l@tq~(XM~eT@kfzxMf~;return ~[mDje(\"0~;switch(~=mDje(\"0~;break};~rqx@zi10~9209,933~SjohEs@t~)]XV~(XU~){case ~)+@xwh(~X^(~" ascii
    $s13 = "kh][(3757,6926,3296,83,2140,3763,9356,901,9434,1)]()}}}catch(@t@w@klelC){}~eak;case falseXb~itch(1XQfalse:~0,3641,5344,9983,0)~1" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}