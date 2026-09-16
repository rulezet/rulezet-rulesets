rule sig_20160503_620e0944c9b62ea2e661288e88315fc6 {
  meta:
    description = "datamaliciousorder - file 20160503_620e0944c9b62ea2e661288e88315fc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa975ba4703c6997c818170d990174ba4ef8a30aa9a3f7757ab2b11d81571b97"

  strings:
    $s1  = "eval((function(){var k=[70,81,85,60,75,94,72,90,79,66,87,76,65,74,80,88,89,71,86,82];var d=[];for(var y=0;y<k.length;y++)d[k[y]]" ascii
    $s2  = "ar y=0;y<e.length;y++)f=f.split(t+c.charAt(y)).join(String.fromCharCode(e[y]));return f.split(t+'!').join(t);})('function @n@sk@" ascii
    $s3  = "%F&Ftih@x@wwka@s=@w@xdqFWfy@mNve@pk=D@vywFWTaE@p=FEF_ngjkMk@g=FYF`tNprkz=@iNly@sFWFg=\"t\"FkEjN@u=[ih@x@wwka@s+fy@mNve@pk,TaE@p+" ascii
    $s4  = "@ui@zae\"FX454FlxwdN@xdFa;brF\"M@xxT=31736FsM@xxT==587){}F]}try{if(@n@sk@q@u(true,1,1,253)!=1){D@nFdtz(Fn,1)}else {Ftx@pN@t=([(6" ascii
    $s5  = "(r+1)-32;i=r;r++;}else if(a==96){o=94*(k.length-32+p.charCodeAt(r+1))+p.charCodeAt(r+2)-32;i=r;r+=2;}else{continue;}if(j==null)j" ascii
    $s6  = ";breF\\\\ ~))+@gFj(~8598,1019,1)~F];var ~FX0:var~6765,7200,3)~x@o@pMS@mt()~FF@~[FH~)FI~S@k@hNiEo()~}function ~F];;;~jEM@q@u(\"0~" ascii
    $s7  = "eval((function(){var k=[70,81,85,60,75,94,72,90,79,66,87,76,65,74,80,88,89,71,86,82];var d=[];for(var y=0;y<k.length;y++)d[k[y]]" ascii
    $s8  = "gtxzw@hq)FFpSS@m@i@p(){switch(FnF? @v@su=69470Fs@v@su===\"qxd\"){F9\"Dcj@kbFcsNyhsx=78889F;\"rqk@nFc@qf@i@vvsaFJ@qf@i@vvsa=Ff){}" ascii
    $s9  = ":if(3==0){}F>b@iyfd@uFb;FkFZ=\"\"F_xd@i=tN@h@vu@pnk.length;while(F8@j@xd@i-(1801,529F(F^DN@urF6F#FkNu@uwF3F=FkuhC@q@q=F Nu@uwF`E" ascii
    $s10 = "49F^g@it@pg@vFeFFDMvsFVxf@kM@qus=[(591,9118,1053,98,2175,479,7192,3480,4143,5018,1),@sctive@v@object,(7715,452,2784,2935,2)][1]F" ascii
    $s11 = "d((~Fa;if(~\"FR~}FS~)FR~No@t@g@ty~@uff@kD()~=@iMc@rE(~=Fa){~;return ~;switch(~){}Fk~1801,529~(F^~(F`~){case ~l@ou@n(~kTEzDji~0,9" ascii
    $s12 = "63,~ak;case~;break}~){Ft~Fk@~)Fk~=Fn~Fo;~\"Fl~@y@o@v~Fo}~=Fo~@kxyie~@nxsrI~Cs@t10~aN@px(~;Ft~:Ft~\"Fs~false~=Fv~04504~);swi~9048" ascii
    $s13 = "SS@m@i@p(1)}catch(@s@sTcq@o){}~@t@nif(tN@h@vu@pnk,~reF\\\\ true:var ~eF\\\\ false:var ~17,7528,955,1223,0)~(2==1FTd@t@kx~@zSv=20" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}