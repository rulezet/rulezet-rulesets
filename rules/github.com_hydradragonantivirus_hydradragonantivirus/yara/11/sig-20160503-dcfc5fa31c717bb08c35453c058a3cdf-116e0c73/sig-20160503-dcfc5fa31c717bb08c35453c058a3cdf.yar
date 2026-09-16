rule sig_20160503_dcfc5fa31c717bb08c35453c058a3cdf {
  meta:
    description = "datamaliciousorder - file 20160503_dcfc5fa31c717bb08c35453c058a3cdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92415fb2ca1ce2134139def66f1e0d5db0547f270e9861a1a92ad671e2eb4ec4"

  strings:
    $s1  = "ar c=0;c<f.length;c++)t=t.split(r+i.charAt(c)).join(String.fromCharCode(f[c]));return t.split(r+'!').join(r);})('function DSwmr(" ascii
    $s2  = "eval((function(){var e=[87,71,66,70,75,88,89,82,80,72,60,90,76,94,74,81,79,86,85,65];var q=[];for(var c=0;c<e.length;c++)q[e[c]]" ascii
    $s3  = "(s+1)-32;m=s;s++;}else if(j==96){v=94*(e.length-32+y.charCodeAt(s+1))+y.charCodeAt(s+2)-32;m=s;s+=2;}else{continue;}if(p==null)p" ascii
    $s4  = "eval((function(){var e=[87,71,66,70,75,88,89,82,80,72,60,90,76,94,74,81,79,86,85,65];var q=[];for(var c=0;c<e.length;c++)q[e[c]]" ascii
    $s5  = "dff){dlddWA18049009G!06014020008Wr8W{lfdff)WIIz@j@xzI@j(Wamp@l=f@ixqW\\\\e@mc@g@yx=@pjI@oNW\\\\qy@ylg=e@mc@g@yxWA37055023Wp20310" ascii
    $s6  = "gdE@j@ya(\"0~==trueWa~[gdE@j@ya(\"0~=(5147,9780,~@lpEd@jT@n@n~r Twqr=\"Mrd@~WI@~))+W_(~(149,2190,2~xTo@i@o@v()~}function ~falseW" ascii
    $s7  = "jj@iN\"W>542Wm@ofym@y=31838Wnofym@y=WPvar kN@jWdW;true:if(5===722){}WWWqo@lm@l@uEW^;WbnsvWU@nwMW-W<W2W\"W:W5WDW4 W3W`W+W=;WlNpzn" ascii
    $s8  = "engthWbrpIWBW#W!Wx7===556){}WlWQ=\"\"Wlmlsq@vmh=d@puk.length;while(Wy@qmlsq@vmh-WG)WaCu@x@o@psWBW#W!WbuaaWfG W)Wlb@rD@kW$@uaaWeo" ascii
    $s9  = "ly@nvh@p(~WV@~\"WV~};sWh~wD@l@kk()~=Wd){~@kSz@xo@x~);sWh~6510,3984~falseWx~=@hmac@k(~;return ~;break};~W]1~(Wa@~Wbo@~{var wpf~(W" ascii
    $s10 = "~){case ~Wd;~I@vdmt(~ @k@ry=~){var ~Wl@~\"Wm~=false~)Wl~=Wy+~if(6==~witch(~@r@j@m~\");var~@yja10~;var ~:var ~Wx@~=true~00600~var" ascii
    $s11 = "break;case~if(@w@luor==1){va~,8055,9736,5826,~){W;~))+WK(~WW;;var ~@w@luor=19076;~}W>~\"q@wnM@mip\":v~b@m@ut=74554;~;break;case " ascii
    $s12 = "#0~0,4636,8926,3050,0)~reak;case trueWm~3749,7882,7495,568~=@m@lxI@n@s(d@puk,~W(e~e@k@oh=WP};~l@imW^var Ed~k@oh=27292WxEdS~3,63," ascii
    $s13 = "5301,9426,1)~;@nsvWA~true}WWvar ~=trueW>~WR4){case ~falseW>~W69~fvTCzWA~9296,7687,9074,3)~ar fyww@rW^b~141:if(3===1){var~pftw\"}" ascii
    $s14 = "169,5587,3932,8170,6027,2645,8223,9802,1),Iz@j@xzI@j][(7636,5536,7169,5587,3932,8170,6027,2645,8223,9802,1)]()}}catch(@vjqC){}~W" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}