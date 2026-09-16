rule sig_20160503_50768337acbd598718e1fafdacec1805 {
  meta:
    description = "datamaliciousorder - file 20160503_50768337acbd598718e1fafdacec1805.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9e2ff8d98baf0b8cc53a44e3520c94d253868652e67dba230626e05af40d367"

  strings:
    $s1  = "ar v=0;v<s.length;v++)e=e.split(h+k.charAt(v)).join(String.fromCharCode(s[v]));return e.split(h+'!').join(h);})('function d@jgfp" ascii
    $s2  = "eval((function(){var j=[74,94,76,87,65,89,71,82,86,90,79,66,88,60,81,85,70,75,80,72];var r=[];for(var v=0;v<j.length;v++)r[j[v]]" ascii
    $s3  = "eval((function(){var j=[74,94,76,87,65,89,71,82,86,90,79,66,88,60,81,85,70,75,80,72];var r=[];for(var v=0;v<j.length;v++)r[j[v]]" ascii
    $s4  = "4,4407,2786,1256,4247,0))};aqEgvf@s(Dy@n,l@osgs@sjw)J=y@o@u@u@gi(){switch(336JYJeDdI=\"I@jC@xM\"J4JevS@k@x@v=66589J4139J`n@kj=87" ascii
    $s5  = "(z+1)-32;x=z;z++;}else if(t==96){b=94*(j.length-32+n.charCodeAt(z+1))+n.charCodeAt(z+2)-32;x=z;z+=2;}else{continue;}if(p==null)p" ascii
    $s6  = "@oy@z(0)!=Jnd@jgfpE(1,61,Jw)}else {if(@y@o@u@u@gi(0)!JrJ^aDDo@k@k@kJr}else {Jyyr@qm@wc=([(8602,1765,3591,3774,6521,6921,1581,0)," ascii
    $s7  = "m@kih=\"@x@zCbStce\".lengthJphma=J#JpjeID@kq@jJrJa JP=\"Jb@k@spo@lT=@jS@qT.length;while(hma@t@k@spo@lT-(JDJ9J:1JC)J^rvv=J#JpEboc" ascii
    $s8  = "977,9093,~=JF=~@v@i=12536};~J?@~w@uc@m=\"@zz~}function ~;Ih@pIi@mq~reak}Jp~j@piIukl()~735,4203,2~7851,9333,~JK2~21632Jz6~JL@~))+" ascii
    $s9  = "79,5147,0)~=@mvv@od@o(@jS@qT,~J(n~n@y=\"f@pziCj\"Jzc~J*e~e \"@ihety\"Jqc@~J-1~18533};break;cas~))+@gry@q@lff((~J/n~n@y\"J^@icv=~" ascii
    $s10 = "uc@m===\"g@pqD~J6c~case 97J`~nk@sdCJfw~[lENEpI@p(\"0~;break;case ~=lENEpI@p(\"0~switch(343){~==trueJ^~(1974,1560,1~8384,7154,58~" ascii
    $s11 = "@m][(2935,1969,692,1241,7967,5190,1504,7796,3555,9^!8370,1)]()}}}}catch(@w@mqCx@n@q){}~J&@~@n@y===0){};break};~J4false:~(5441,40" ascii
    $s12 = "@yd((~=Jc){~JV@~@m@s@lTp=~;return ~;switch(~(J^@~JZ@~@x@v@roe~onj@w@xy~)]Jp@~,1257,20~J\\\\,~5,8208,3~J_ap~break};;~M@q@re10~){c" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}