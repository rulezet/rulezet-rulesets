rule sig_20160503_7e53eb1dddb86c602fe40a347b98ef12 {
  meta:
    description = "datamaliciousorder - file 20160503_7e53eb1dddb86c602fe40a347b98ef12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4560c6a7cb80145724bf92bd7b5d91fd54613ed153d3372a4dfb3e9c0043d361"

  strings:
    $s1  = "eval((function(){var z=[70,65,89,87,82,79,66,90,76,86,71,80,74,72,81,75,88,85,94,60];var r=[];for(var e=0;e<z.length;e++)r[z[e]]" ascii
    $s2  = "ar e=0;e<c.length;e++)y=y.split(t+j.charAt(e)).join(String.fromCharCode(c[e]));return y.split(t+'!').join(t);})('function tg@nlI" ascii
    $s3  = "switch(truF_325FrxtSuC=30845FB\"f@iI@qlz@jz\"Frrw@nw@g=\"CrckeFurw@nw@g===0FmF o@qTp@pFiF%@rfkzM@g@i=33045FkFQ1)Fj\"@tet@hv@r\"F" ascii
    $s4  = "MFNFy@ut@iFiFQ5FUFyE@vv@p@gpFsF%lEM@sh=75448FzlEM@sh==FsFfuwEdc@pFsFJFyFR=\"Fhr@j@mkSsmy=@r@nM@icew.length;while(FI@zr@j@mkSsmy-" ascii
    $s5  = "eval((function(){var z=[70,65,89,87,82,79,66,90,76,86,71,80,74,72,81,75,88,85,94,60];var r=[];for(var e=0;e<z.length;e++)r[z[e]]" ascii
    $s6  = "(s+1)-32;l=s;s++;}else if(h==96){u=94*(z.length-32+x.charCodeAt(s+1))+x.charCodeAt(s+2)-32;l=s;s+=2;}else{continue;}if(f==null)f" ascii
    $s7  = "@o@q@nk~}F^;;~}function ~ 1Frok@~F[@~=Fi){~22,9195,1~\"F[~}FZ~@pza@x@lb~yCx@uCg()~]F[~)Fj1:~Itik@hN()~=Fs){}~ugTa@t@t(~(Fb~;swit" ascii
    $s8  = " ~FI);~\"FB~tM=\"I@jN@i\";i~witch(4){case~6,1874,9205,3~Fk;case ~@spo@i@s@j()~v@nwqr@szu10~))+@Fp(~FK@~E@p@xNs@h@h~i@n@tTC@g()~s" ascii
    $s9  = "h(~;return ~Fc@~{switch(~Fk};~e)Fj~);hTzIak~=kf@nSs(~Ff@~(Fg~(jMS@jb~p@poy@n~){Fy~)Fq~\"Fq~=A!e~{case ~;break~c@q@mh~){};br~Fs;~" ascii
    $s10 = "4987,1),qI@ow@t][(1230,2578,3406,4987,1)]()}}catch(u@o@w@w@ga){}~eak;case falseFr~E@hm@jC(@r@nM@icew,~F$6~6,5803,8420,6290,0)~22" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}