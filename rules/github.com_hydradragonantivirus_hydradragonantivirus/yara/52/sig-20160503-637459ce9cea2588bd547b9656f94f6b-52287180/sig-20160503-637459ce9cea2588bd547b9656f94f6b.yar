rule sig_20160503_637459ce9cea2588bd547b9656f94f6b {
  meta:
    description = "datamaliciousorder - file 20160503_637459ce9cea2588bd547b9656f94f6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8928439ae66ab9907ad42b2d80a1593a2fbf068fc1e17178888428f16bbd0f55"

  strings:
    $s1  = "nt@i\"}try{@wthi@ku(false,true,555,\"iCp@z@zeED\");l@ldC(1);@j@mndk(true)^rCN@xnx@lf=([(9487,5745,0),@yScript])[(2010,261,5876,3" ascii
    $s2  = "ar o=0;o<y.length;o++)t=t.split(m+q.charAt(o)).join(String.fromCharCode(y[o]));return t.split(m+'!').join(m);})('function @wthi@" ascii
    $s3  = "eval((function(){var k=[94,60,79,80,71,74,66,86,90,72,88,85,75,65,81,70,76,82,87,89];var j=[];for(var o=0;o<k.length;o++)j[k[o]]" ascii
    $s4  = "(v+1)-32;z=v;v++;}else if(r==96){f=94*(k.length-32+s.charCodeAt(v+1))+s.charCodeAt(v+2)-32;z=v;v+=2;}else{continue;}if(a==null)a" ascii
    $s5  = "004016045032046051<!54046048\"^cl@vT@p^HcCs@i^x^i^C30048035023002023\")]==(3569,4610,7519,9437,1165,5548,1738,9697,200)){switch(" ascii
    $s6  = "pm@j,j@wMr@xE@z,false);sw^L ^ozcf^M^? @^|^@^\\\\^;^8^z^96^^3;^i^C62^{4007\")]^bcCs@i^E30<!48010007016033035006127011058033033017" ascii
    $s7  = "eval((function(){var k=[94,60,79,80,71,74,66,86,90,72,88,85,75,65,81,70,76,82,87,89];var j=[];for(var o=0;o<k.length;o++)j[k[o]]" ascii
    $s8  = "s@n@n=\"E@uiiwT^vz@s@n@n===758)^g^Z=\"^fzcNp@i=N@q@nMvy@w@r.length;while(^w@h@zcNp@i-(30^5^6,875,2)^awhc@ohn=^%^$^nsgc@l@k^h^<^4" ascii
    $s9  = "3,5827,3~itch(2){case~u=\"bNsp@v\";i~@z@p@igiw@t(~reak};;^r~^R@~Cw@v@nnIv()~}function ~\"@q@xo\":va~^]@~))+@mIt((~\"^]~false;if(" ascii
    $s10 = "%3~35,453,9939,1886,0)~(7827,8720,3115,99~;case 655^s@m@q~if(o@y@kt@x===1){}~^.i~t=\"t@z@vck@ss\"^}~ak};if(2===598){};~se true:i" ascii
    $s11 = "}^}ak;c~\"^D~ Ia@r^p};~[@y@v@vtf(\"0~^}ak;case ~=@y@v@vtf(\"0~m@y@u@iTC@ly~7,1493,5892,~=@zq@py@r@i(~@jm@y@i@js()~199,8065,473~," ascii
    $s12 = "Sz][(2010,261,5876,3099,6411,8153,7146,2345,51,2118,4185,1)]()}}catch(fSNqn@mv){}~switch(false^e~^D1:var @~@sETD(N@q@nMvy@w@r,~^" ascii
    $s13 = "pyk()~=^p){~Dvsnf@t@u~==1^t ~ase \"Swo@~;return ~^}ak};~;switch(~y@k@sug@~^t @~()^r~)^n~(^t ~){case ~\"^n~{}^r~=^w+~iSe@pit~rvsv" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}