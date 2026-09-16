rule sig_20160503_3eb8b7fcc2e69a11c1ead9c22b272441 {
  meta:
    description = "datamaliciousorder - file 20160503_3eb8b7fcc2e69a11c1ead9c22b272441.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5738c462d03e3858d566e13a13c16d8b9e78adb2f942f5c06dabd9d7b28e57f8"

  strings:
    $s1  = "ar i=0;i<h.length;i++)r=r.split(j+a.charAt(i)).join(String.fromCharCode(h[i]));return r.split(j+'!').join(j);})('function @xv@ua" ascii
    $s2  = "eval((function(){var c=[79,71,74,80,81,94,85,76,82,88,65,90,86,87,66,75,89,70,72,60];var q=[];for(var i=0;i<c.length;i++)q[c[i]]" ascii
    $s3  = "\\OxMTC@y=OoOggIlloI=O_Olfx@v=\"dOme@u@r@hN@m=megnOgngi=\"@qOmxelN@ke=\"tOmy@vwh=[@s@nEa,f@hw@m@k@j,yGBvCm,uzmioq@s@i,MTC@y,gIll" ascii
    $s4  = "rCxNTr=Ojc@nxz@yG!qOfO,29GI61G(17G&G7OC24046G$26027061017034G$60061051\")]OlTn@mG,OUTn@mG,OETuayCTj=\"@jgnu@nv@r\"}OxEr@tsc@p=(6" ascii
    $s5  = "eval((function(){var c=[79,71,74,80,81,94,85,76,82,88,65,90,86,87,66,75,89,70,72,60];var q=[];for(var i=0;i<c.length;i++)q[c[i]]" ascii
    $s6  = "96,3799,4137,5601,7281,200)){switch(296Oh\"vju@pmp@yy\"G\\'1==\"I@j@wa@wdT\"O8\"@x@xiE@xO| yi@xiS@ns=81948OXG+N@v@ru@g@nb@g=Oj@o" ascii
    $s7  = "(t+1)-32;x=t;t++;}else if(b==96){u=94*(c.length-32+o.charCodeAt(t+1))+o.charCodeAt(t+2)-32;x=t;t+=2;}else{continue;}if(z==null)z" ascii
    $s8  = "83,8206,~}function ~falseOy~=Ei@n@m(\"0~88Oy@nl~[Ei@n@m(\"0~)Oa@~Or;if(~@gwgebg@nx~591Oy@n~G)ak};;;~w@wCc@uq10~\"Oa~]Oa~m@u@gCt(" ascii
    $s9  = "GO@);OsOd@v@n@m}OaGKOKgibc(dDhll,r@rIy,N@yp@w,N@terp@nOkSE@q=25501Oa0OKiw@rc@k(Oknz@gf@u=[(6234,7677,5785,58G0200,G?,31G/25,1),@" ascii
    $s10 = "=\"tqhh~@n@yOS~lgm(@xk@h@ytn,~==falseOk~(3167,8690,1)~(9803,2424,57~==trueOk~G)ak;case ~itch(1){case~OO@~break}Ox~@kc@u@u@md(~(1" ascii
    $s11 = "(@xk@h@ytn,Os~)Oc5){case ~3040,3831,7336,2)~O6t~tlcj\"Okf@s@i@~p=\"@rf@pCe@k@k\"};~@g@u=\"N@j@o@k@k\"}~O<=~=falseOk@k@r~ak}G%6==" ascii
    $s12 = "oyvj@r){[(6865,5196,5413G-6,1),mD@r@nmD@x][(6865,5196,5413G-6,1)]()}}catch(qg@ih){}~O#8~87,4809,844,6746,0)~witch(falseOh~,3615," ascii
    $s13 = "4881,6728,10~O\\'C~C=16521G)ak;case~M@ph=43022G)ak};~th@jbi\"OySkk@x~break;case 1Oy~5370G%5==0){};s~break;case 0Oy~=0O8~@g@nb@gO" ascii
    $s14 = "xTOmbG@v=\"e@wgq@wE@h\"Op GJ\"Omt@tNzIly=@xk@h@ytn.length;while(Os@zt@tNzIly-ONO/Oku@od@veCaOnO#O!Ox@y@itoOdOFOx@nxlk=OD@y@itoOl" ascii
    $s15 = "@jks@i@y~Oqif(~v@jlen@t(~(Ok@~;return ~))+G8(~;switch(~=Os+~@xEd=\"S@~);N@v@ru~(Ol~){case ~}G)ak~k@xezI(~){G+~)Ox~\"Ox~=(1299~Tb" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}