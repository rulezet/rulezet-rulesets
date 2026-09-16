rule sig_20160503_3517f718b87c7f5c539f375f36824834 {
  meta:
    description = "datamaliciousorder - file 20160503_3517f718b87c7f5c539f375f36824834.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "173f8a35548e8d135b1053843c042eb30c9cbcba751b5c83116d98bf9f724603"

  strings:
    $s1  = "eval((function(){var m=[76,71,65,80,79,85,88,82,81,87,75,60,74,66,90,86,70,89,72,94];var x=[];for(var d=0;d<m.length;d++)x[m[d]]" ascii
    $s2  = "w=\"oSvqqM@x\"}else {LinIhDi=([(8807,3746,5519,8598,7704,3883,5175,9126,9613,6738,0),@pScript])[(Lv,8319,4029,4438,1619,321Lm3,7" ascii
    $s3  = "L]G\"bL/@w@jg=51670;break}LV0LZtrue:if(5===451L4\"@un@x\":La0G\"bL/hI@pSz=\"c@ph@jquI\"L:\"MNbC@j@m\"Lhkl@t@vgh=\"ohenNT@j\";bre" ascii
    $s4  = "ar d=0;d<f.length;d++)k=k.split(r+i.charAt(d)).join(String.fromCharCode(f[d]));return k.split(r+'!').join(r);})('function tz@w@k" ascii
    $s5  = "g@wekj=71293Lc L|=\"\"Lgr@y@m@w=nchSlzpg.length;while(LA@rr@y@m@w-LBL+L^@ic@vq@v@vzd=(96L&L\"L!Lg@h@j@vL8L)Lgn@wh@t@xL#@h@j@vL_g" ascii
    $s6  = "u+eirmS+@px@n+L=][@vr@o@xqzj]LKlv@n@u@k@ylxLGgz@v(@qo@u@ppNID){switch(1LZ1LhcIhqoy@pLHcIhqoy@p===0L40:LaLCd@h@sM@i=18589}L(LijzC" ascii
    $s7  = "h=\"Na@s@y@o@nLjy@gklN@hLQfkd=4Ly}L:Ll @n@nmDcyL`;break}}try{if(p@xcq@mhy(598)==0){@m@x@tc@j(1)}G tz@w@k(0,\"cti\",true,0)!LC@n@" ascii
    $s8  = "eval((function(){var m=[76,71,65,80,79,85,88,82,81,87,75,60,74,66,90,86,70,89,72,94];var x=[];for(var d=0;d<m.length;d++)x[m[d]]" ascii
    $s9  = "r@jSb@j)Lrm@uL357034044045027031\")]==(1167,8262,1907,7260,34Lq16,1054,1272,200)){switch(4LZ745Lhnbx=\"Ch@uo\";L*if(2===1L4Ll MD" ascii
    $s10 = "(q+1)-32;c=q;q++;}else if(h==96){e=94*(m.length-32+l.charCodeAt(q+1))+l.charCodeAt(q+2)-32;c=q;q+=2;}else{continue;}if(u==null)u" ascii
    $s11 = "\"0~=S@nma@x(\"0~LG@~@oy@q@qnsvE~(5763,2458,~=trueL^~iLG~D@qIMST@j@y~+d@w@ttk@p(~}function ~L`;if(~)LX(~w@pCbf@m@h~LS@~\"LS~eLY~" ascii
    $s12 = "@itz=\"Ixut\";var~mml@xL>~){}L:~(8200,398,5779,~))LF(~LY;;var ~=LA+~LA);~;break;case ~@t@o@k@igvu(~L^kC@iuo~fu@l@sc@ld@x~[S@nma@" ascii
    $s13 = "\";var~L:true:~(8474,3234,135,1)~break;case Lo:~5702,5538,9922,2)~L2 ~ @ux@j@kihL`;~);@pToL>~reak;case 1Lh~6722,2689,633,3)~L56~" ascii
    $s14 = "67,5707,5305,745,5)G kuDc){[(Lv,8319,4029,4438,1619,321Lm3,7369,1),Epwa][(Lv,8319,4029,4438,1619,321Lm3,7369,1)]()}}}catch(@lm@j" ascii
    $s15 = "Lg@~a@g@t@w()~@tqoM@m10~==0L^~)LV~;return ~(L^@~L[@~;switch(~rSqy@tnk~)+Evw@m(~;break};~){case ~(L_~E@i@le(~==Lk~){Ls~)Lg~=Lo~if" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}