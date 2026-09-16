rule sig_20160503_d502b7b9569d0719eef218eb48306a8f {
  meta:
    description = "datamaliciousorder - file 20160503_d502b7b9569d0719eef218eb48306a8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ee0ed2f3bbd440d958f59d9593ae01d6fcbad63a23ec430643d1796d5d6bd09"

  strings:
    $s1  = "ue)!A_AxjEIu=68670}else {if(@iI@kd@k(71,An,0)=ANo@juC=([(9304,8011,2609,3222,3405,0),@jScript])[(3300,9619,6106,4990,7158,7531,1" ascii
    $s2  = "ar o=0;o<h.length;o++)m=m.split(l+s.charAt(o)).join(String.fromCharCode(h[o]));return m.split(l+'!').join(l);})('function @iI@kd" ascii
    $s3  = "eval((function(){var g=[65,90,71,87,85,80,94,79,70,81,76,88,86,75,89,72,60,82,74,66];var t=[];for(var o=0;o<g.length;o++)t[g[o]]" ascii
    $s4  = "eval((function(){var g=[65,90,71,87,85,80,94,79,70,81,76,88,86,75,89,72,60,82,74,66];var t=[];for(var o=0;o<g.length;o++)t[g[o]]" ascii
    $s5  = "y=\"o\"AJobbCi@z@pyAAraejlAKpTl@t=\"c\"AHpTl@tAAr@n@td@lAKhNS=\"a\"AHhNSAAqbgp@nAKs@ksw=\"e\"AHs@kswAAiSqpd@uAKsCg=\"h\"AHsCgADC" ascii
    $s6  = "p@z@rs=ANr@z@uE@gb@oAe}AlAS=\"\"Aln@qE@x=@iqn.length;while(Ak@wn@qE@x-(9A,AZzgj@zA]A AIA!Alxq@y@rx@trATAFA*7678A+A(Alve@yA=xq@y@" ascii
    $s7  = "(k+1)-32;z=k;k++;}else if(u==96){r=94*(g.length-32+c.charCodeAt(k+1))+c.charCodeAt(k+2)-32;z=k;k+=2;}else{continue;}if(f==null)f" ascii
    $s8  = "90,7158,7531,1326,5713,3842Af9090,7956,1)]()}}}}catch(EIsSgf){}~5776,4297,1842,3800~0,2428,6729,7640,0)~A%s~seAlzv@irp=true;~A&;" ascii
    $s9  = "7~@sqcs@s=39893~I@zAE~=@jdk@k(@iqn,~Atk;case ~f(i@vT@q@h==~5,3992,3490,~AD@~@r@n@td@l()~C@tu@sx@uDN~}function ~[gAO~(1274,7295~)" ascii
    $s10 = "~AM0){case ~if(1==\"eS@k@qu\")~A4i~{var psrAe};~k;case trueAm~A66~6==0){}AQ~A>\"@~h@iuciw@k\":if(~}A>~,2554,3563,3)~716,9763,778" ascii
    $s11 = ")Ab(~AJ@~,5468,295~;return ~AW@~)+akqM((~;switch(~=1Ad~ngznq(\"0~Ae){~;Ah;~AV@~i@jcMujC~=Ak+~670Am~(Ac~(Ad~}Al@~){case ~Ad@~d@zq" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}