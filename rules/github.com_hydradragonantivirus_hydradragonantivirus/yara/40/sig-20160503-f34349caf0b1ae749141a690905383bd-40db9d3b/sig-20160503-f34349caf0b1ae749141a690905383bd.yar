rule sig_20160503_f34349caf0b1ae749141a690905383bd {
  meta:
    description = "datamaliciousorder - file 20160503_f34349caf0b1ae749141a690905383bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e13e0590f2f8a5d4268b4ad0fc41bbf3c355e4684ac6fd3be4afc26966201ce"

  strings:
    $s1  = "eval((function(){var z=[79,80,85,71,86,94,87,90,81,66,74,72,88,89,75,82,76,65,60,70];var g=[];for(var p=0;p<z.length;p++)g[z[p]]" ascii
    $s2  = "ar p=0;p<o.length;p++)w=w.split(q+y.charAt(p)).join(String.fromCharCode(o[p]));return w.split(q+'!').join(q);})('function EtTmj(" ascii
    $s3  = ",4753,9671,2563,2)][1]OTaS@gidTg@iOLCP:hOWk@uqbas@u=O>02010057007031121102055029030036037012020\"OOk@uqbas@uOJqf@uv(dldd,lfdff){" ascii
    $s4  = "0:Ox~712,1105,679~,8218,9372,3~cDxrN=15879;~OP);~;Oi;var ~OL@~idtj@tl=\"Es~}function ~;Oi;;;~{Ox@vv@z~)OT@~x@ihx@txNc~,3279,8001" ascii
    $s5  = "eval((function(){var z=[79,80,85,71,86,94,87,90,81,66,74,72,88,89,75,82,76,65,60,70];var g=[];for(var p=0;p<z.length;p++)g[z[p]]" ascii
    $s6  = "(u+1)-32;j=u;u++;}else if(f==96){h=94*(z.length-32+n.charCodeAt(u+1))+n.charCodeAt(u+2)-32;j=u;u+=2;}else{continue;}if(r==null)r" ascii
    $s7  = "Of@r@iap@nm=\"@qql@tOmr@iap@nm==O]@rS@nop=\"yErg@z\"}OIP:mOdOwP:m==OCTmzC@rh=\"@jw@u@k@i\"}OrP(=\"OejD@nD@ndd=@zI@q.length;while" ascii
    $s8  = "0Oc@hji@s@pOhOMOx@k@qn=(18P)325,990,9644,0)OkO931P618O|39P339001\")]=@k@qnOU\"kle@qDO[false:Ox@inNpx=72555O=68Oz2==OC@uie@k@kyOh" ascii
    $s9  = "428,1),M@m@ip@z@z@m]Ou8,2719,4079,3420,1016,5268,7547,8012,6428,1)]()}}else {Ox@va@zCOd}}catch(@gk@zTM){}~eak;case false:Ox~1,84" ascii
    $s10 = "(@zI@q,~O4s~se 427:Oxz@xx=~))+q@n@sqTj@j((~wgM@hm=15179;br~6O`1:var M~O66~){}O=~@vq@o@joOd;~g@n@s\"O}ak;ca~ak;case 0:Ox~=13486OU" ascii
    $s11 = "\"OT~ @i@z@nn@~;return ~;sOn~(Ob@~O_@~ @hyqz@x~rue:Ox~==true){~\"O`~Mb@pdDI(~=1Oc~@zqt@r10~(Oc~){case ~2913,11~)Or~){Ox~=false~" ascii
    $s12 = "O<2~21,5954,6425,1~eO:~[O>~O?,~,4320,5282,89~O}ak;case ~@j@ov@q@j(\"0~77,5590,3423~OP+(~97,2669,1996~,1983,9537,2~=falseOc~{case" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}