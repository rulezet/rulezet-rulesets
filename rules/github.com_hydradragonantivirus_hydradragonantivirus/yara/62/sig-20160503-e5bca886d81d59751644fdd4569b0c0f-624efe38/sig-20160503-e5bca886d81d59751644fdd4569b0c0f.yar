rule sig_20160503_e5bca886d81d59751644fdd4569b0c0f {
  meta:
    description = "datamaliciousorder - file 20160503_e5bca886d81d59751644fdd4569b0c0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "023e74f492e2b32d8878083a887baae57072144b8b63d5491b20f1ffc95b83c9"

  strings:
    $s1  = "eval((function(){var z=[76,85,79,70,81,74,65,86,72,88,94,82,80,75,60,89,71,87,66,90];var v=[];for(var f=0;f<z.length;f++)v[z[f]]" ascii
    $s2  = "ar f=0;f<x.length;f++)p=p.split(o+h.charAt(f)).join(String.fromCharCode(x[f]));return p.split(o+'!').join(o);})('function E@wS@w" ascii
    $s3  = "length;while(Lf@uc@zg-(4U0662L;L6LbyCjbS@yLlL\\'L#L!Lckzl@o@tq@n@lLZLiL4LrLdhcofL9@kzl@o@tq@n@lLdCI@sq@t@rsL9Lf+(4U0662L;L6)LcpU" ascii
    $s4  = "(t+1)-32;y=t;t++;}else if(j==96){c=94*(z.length-32+i.charCodeAt(t+1))+i.charCodeAt(t+2)-32;y=t;t+=2;}else{continue;}if(g==null)g" ascii
    $s5  = "~f@nvf@wve()~lMD@w@o@x@h~}function ~v@j@izCI()~L[@~\"L[~==0Lb~}L^~zi@iI@lt(~pIli@o@zN~Lq;if(~=Lf+(~;return ~L|ak};~(Lb@~;switch(" ascii
    $s6  = "=\"@mLTcvo@suLQNl@tf(){switch(5)LHj@v@k@p@iN=55138LG3:Lul@juviLqL|L/if(1==U$L\\\\if(3==\"@rv@nC@g@z\"Lb@ss@nC=26383}Lpyb@x@ldry=" ascii
    $s7  = "eval((function(){var z=[76,85,79,70,81,74,65,86,72,88,94,82,80,75,60,89,71,87,66,90];var v=[];for(var f=0;f<z.length;f++)v[z[f]]" ascii
    $s8  = "6,5020,651,3770,6381,9638,9824,6105,5280,2992,200)){switch(7)LgLzL}L7r@ja@mCLe}L\"rMU5gp=51471L\\\\Lui@jl=69505Lv6===U$Lpj@g@k@r" ascii
    $s9  = "@mf@ziz@Lk}LvppjeT@s(\"@tod\",Lz,0)!=1LbE@mf@ziz@Lk}else {if(s@tlf@h@iy(fU3,0,53,759)!=1LbE@mf@ziz@Lk}else {Luy@la=([(4754,6739," ascii
    $s10 = "38\")]LpNT@h@z@ky@m=@v@xd@wMgt>(5530,4387,5LsNT@h@z@ky@m){[(628U+19,1),d@vihvx][(628U+19,1)]()}}}}catch(d@pyhz@m){}~L#7~7261,23," ascii
    $s11 = "4U0662~(Ld~@xt@l@v~){Lu~Lp@~)Lp~=fU3~sf@p@g~{case ~;j@g@k~7643,2~wCps@p~tLq~=(4656~Lr)~@np@w(~ww@vxi~;Lu~=Lz~164,1~)Lv~@tu@i~var" ascii
    $s12 = "vflE\"}~L^585){~[@xNLn\"01~if(5==Le)~=@xNLn\"0~L|ak;case ~Lg1:var ~T@l@vw@kiu()~58,5242,3318~@y@j@xm@oC10~reak};;Lp~LQ@~))+Mfi@m" ascii
    $s13 = "reak~L1c~case 681:Lu@w~case true:Lu~ak;case fU3:~@xILq;switc~os=4184L|ak;~ @gn@pch=58461~@r[@xNLn\"0~172,3322,201,6~L;7~72,755,3" ascii
    $s14 = "40,7438,0)~LG1:var ~09,1739,3466,1357,~ mNL0h~h(6)Lgfalse:va~reak;case Lz:var~,437,7358,1474,83~L+}~}LpcIne=72427;~L-@~@p@vzLq;b" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}