rule sig_20160503_9387e2f8856f20ddee71c4f42321f7be {
  meta:
    description = "datamaliciousorder - file 20160503_9387e2f8856f20ddee71c4f42321f7be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32dab04fbc8fb05edce65654e2b4176b5df0871dcf9dee877daf45a42dce3ad7"

  strings:
    $s1  = "eval((function(){var j=[81,71,72,87,60,80,89,86,70,82,79,85,74,76,88,66,65,90,75,94];var i=[];for(var c=0;c<j.length;c++)i[j[c]]" ascii
    $s2  = "ar c=0;c<y.length;c++)p=p.split(s+u.charAt(c)).join(String.fromCharCode(y[c]));return p.split(s+'!').join(s);})('function lsz@p@" ascii
    $s3  = "tfy(@p@G(,mw@tg@i){switch(@p@G(Qi347Qx@p@G(QL@g@ql@n@q=52980Qw@g@ql@n@q==0Qq EmS@ss=\"@tj@wk@hTS\"}Q]@p@G(QiQzQp@snr=52843;brQ @" ascii
    $s4  = "oC.length;while(G\\'@kxtctx-(1562,QbQcQWQ[QR)Qq SC@x@htq=Q6Q%Q\"Qo@wstx@wCw@j=Qu(QMQPQl@p@tjq@ouQB@wstx@wCw@jQliS@oQBQu(1562,QbQ" ascii
    $s5  = "eval((function(){var j=[81,71,72,87,60,80,89,86,70,82,79,85,74,76,88,66,65,90,75,94];var i=[];for(var c=0;c<j.length;c++)i[j[c]]" ascii
    $s6  = "(z+1)-32;t=z;z++;}else if(v==96){x=94*(j.length-32+e.charCodeAt(z+1))+e.charCodeAt(z+2)-32;t=z;z+=2;}else{continue;}if(l==null)l" ascii
    $s7  = "f(~Q}@h@p@~086,1462,~Qc0~Q]\"~dzzexN@pr~3649,4609~;return ~;switch(~(Ql@~Qj@~Q|ak};~Qr){}~3914,730~3,2255,8~f(@gs@w=~@uEe\";if~s" ascii
    $s8  = "88,6868,8221,3451,601,200)){switch(\"j@m@r@w\"Qi0Qx2QL@w@sujbt=51580}Q?525QpCw@t=46047Q?\"@l@mCt\"Qp@yvDju@p=\"en@q@o\"Q?\"mCch" ascii
    $s9  = "jjEiw~Tvh@i@qx@i\"Qx3=~Q4=~=0Qq qo@u@v@w~){}Q`var ~Q8;~Qwx@iufi@if==~;break}Q]~(6719,5602,876~Q?1:~x@iufi@ifQr~\"Qpqeh@l=tr~rueQ" ascii
    $s10 = "j@yN=~SuQ@~=Qm){var ~sQGs~se trueQx4=~Q|ak;case ~[QH~))+mt@ndMn((~=@sljm(@poC,~fv@s@u=84436~QJ@~=trueQq ~0Qp@jjEi~witch(6){ca~l@" ascii
    $s11 = "6015,1),mpi][(6782,6228,5921,8160,5161,5219,9059,8337,6015,1)]()}}catch(@x@vvI){}~eak;case falseQp~Q%9~93,376,3273,1129,0)~==1){" ascii
    $s12 = "iCv\":~l@w@trIn~@t=71866~){case ~(Qq ~gEMEa@q~)Qo~=false~@muC@p~;Q}~:Q}~){var~=Qz~ue;br~==108~G\\'+~)Qw~;if(~:if(~@n@n~true~\")]" ascii
    $s13 = "s@gayg(\"0~\"c@wE@jmlzw~}function ~))+d@l@l((~===0Qq ~3028,6514,~ak};;Qo~case 1:var~514,3913,1~Q[,~,958,531,2~@l@syTk@pC~Q\\\\@~" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}