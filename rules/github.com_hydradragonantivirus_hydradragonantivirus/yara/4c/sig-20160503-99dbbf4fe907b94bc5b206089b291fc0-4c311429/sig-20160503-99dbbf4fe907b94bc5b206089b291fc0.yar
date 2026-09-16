rule sig_20160503_99dbbf4fe907b94bc5b206089b291fc0 {
  meta:
    description = "datamaliciousorder - file 20160503_99dbbf4fe907b94bc5b206089b291fc0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbf2440e4a312cc4c69184ac5f33704b8c7800f3db14da80f30a52933c512427"

  strings:
    $s1  = "eval((function(){var e=[80,89,75,70,88,65,71,86,60,66,82,74,72,87,81,94,79,76,90,85];var b=[];for(var f=0;f<e.length;f++)b[e[f]]" ascii
    $s2  = "ar f=0;f<m.length;f++)s=s.split(n+x.charAt(f)).join(String.fromCharCode(m[f]));return s.split(n+'!').join(n);})('function @svD@s" ascii
    $s3  = "mnc=44027;~x@zlat@m\":v~z=\"ecE@s@g\"~}function ~Piif(~@rxxgjDc@z~=(7595,407~ TIs=56768~P]@~\"P]~))+Pz(~mbt@n@rC=~);Ph~=Po){~Pvy" ascii
    $s4  = "(u+1)-32;j=u;u++;}else if(t==96){a=94*(e.length-32+l.charCodeAt(u+1))+l.charCodeAt(u+2)-32;j=u;u+=2;}else{continue;}if(h==null)h" ascii
    $s5  = "eval((function(){var e=[80,89,75,70,88,65,71,86,60,66,82,74,72,87,81,94,79,76,90,85];var b=[];for(var f=0;f<e.length;f++)b[e[f]]" ascii
    $s6  = "aN@qPtMe@j@h@q@l==692PnlxD@jzEM=33087}P3if(1===1PnIie@y@pf=67649}Paif(3===Ps){}PqP|=\"\"PqtY.m=wf@hEgcD.length;while(Px@otY.m-(7" ascii
    $s7  = "P;9~9,9406,4108,70~PC\"~[lN@h@pjEw(\"0~==falsePn~=lN@h@pjEw(\"0~}Pavar ~9712,2014,733~k;case Ps:~break};;Pq~111,4898,7958~,3844," ascii
    $s8  = "3,2)~PC5~PFu~u@pa===1){var~Pwk;case ~))+Pb(~m\"Pp@u@pa~a=34384Y)@~PQ@~Y(xE@mSD=~qec@i@x@qIi~r CMx=59114~656Pa~ lPd6~@ygb=26176}~" ascii
    $s9  = ";return ~Pf@~ePg~Pe@~Pwk};~ax@jE@p(~0Pplp~pjMtn=15~()Pq~(Pn~){case ~switch(~=Ps;~Px+(~w@nqgtD~39Y74~Pq@~){Y(~=Pr~:Y(~;Y(~=Y/~fal" ascii
    $s10 = ",3617,5786,1)]()}}catch(@rT@nidh){}~P#4~4,1179,8495,4638,0)~P&1~1150,2831,3630,109~=i@xnNgj(wf@hEgcD,~PCtrue:~7,3790,1826,5948,~" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}