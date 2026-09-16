rule sig_20160503_6198839a512aadcd5d020beb83c046a8 {
  meta:
    description = "datamaliciousorder - file 20160503_6198839a512aadcd5d020beb83c046a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8591aa1a0d73a732eeb688004b35b81bbfb499bad22bd83459faf2bb4fe6d9e7"

  strings:
    $s1  = "(1,14,true)!Ws){aMMC(0)}else {Wud@m@rykTE=([(9607,6399,5121,2618,0),@gScript])[(5758,9745,561,400,1700,9342,1Wp M@m@udk=d@m@rykT" ascii
    $s2  = "ar h=0;h<i.length;h++)y=y.split(d+q.charAt(h)).join(String.fromCharCode(i[h]));return y.split(d+'!').join(d);})('function @xmC@m" ascii
    $s3  = "eval((function(){var s=[87,94,81,80,70,79,76,89,75,66,65,74,71,72,88,90,85,86,60,82];var t=[];for(var h=0;h<s.length;h++)t[s[h]]" ascii
    $s4  = "WDgS@wm@svj(zC@n@nm){switch(7W]1:Wup@n@rhDW-1:WuaSnWlW>\"@w@ql@s\":Wuol@l=8500W>\"@m@vMgM\":WuvNz@nWeif(vNz@n===\"oto\"W\\\\mDlh" ascii
    $s5  = "eval((function(){var s=[87,94,81,80,70,79,76,89,75,66,65,74,71,72,88,90,85,86,60,82];var t=[];for(var h=0;h<s.length;h++)t[s[h]]" ascii
    $s6  = "~Wg{var ~WH@~j@uk@rgkM()~)+@gqw@tg((~=WX+(~}function ~==0W\\\\~WX);~\"WT~)WT~true:Wu~=Wl){~)WV~kgIEkf@pn~y@xbn@o()~=@ob@ssN(~Ws;" ascii
    $s7  = "(n+1)-32;r=n;n++;}else if(a==96){u=94*(s.length-32+e.charCodeAt(n+1))+e.charCodeAt(n+2)-32;r=n;n+=2;}else{continue;}if(w==null)w" ascii
    $s8  = "@zNM@nfWeif(hS@zNM@nfWg{W:EpCMr=\"kgi@itCq\"WbWc=\"Wj@n@g@s@l=@kM@gIgj.length;while(WX@y@n@g@s@l-(325W)W\\\\rxcwkpy@o=W&WqvjvWGW" ascii
    $s9  = "l@ovSkr\"WhE@qfwrWo;break}WV679W]WtWYtrueW1\"z@o@lr@i\"Wii@oz@ws=82586;break}WV1W]0WY131W11WY763WhN@n@l=62690};brW vEIwd@g=\"i@v" ascii
    $s10 = "witch(7W]591WirE@kWlW>WMI@iE=35907WvI@iE==1WhMv@to=64680}W>\"@lIgScv@r\":Wuu@n@v@v=\"i@lpES@zWru@n@v@v=WIx@j@l@p=6828}W7if(5==\"" ascii
    $s11 = "p@kpe@nyW-\"kvv\":if(7==0Whd@j@q@ii@zj=40260W:@t@v@j@ky@p=\"@xi@ka@zj\";;;wlwbW560030Wx05WzNu@s@o@x,tkf,false);vaW4W/W+3;wlwbW53" ascii
    $s12 = "==(6160,7287,200)){switch(3W]WMiIm@g@m@rW-\"a@u@zTxi@rc\":WuaN@isj@sSW-WM@sh@tpS@rfWS@sh@tpS@rf===\"@m@md\"){};brW o@gjsc@nWlWUi" ascii
    $s13 = "u@iMimh===\"enyI\"W1\"qos@mh\"WY534W\\\\pwCu=\"Mb@pa\"}W7WugyIlg=\"bd@xn\"W>false:Wm743WhDN@s@ql@u@lWsW:aDedEi@n=76437WvaDedEi@n" ascii
    $s14 = ",561,400,1700,9342,1),n@mzTe][(5758,9745,561,400,1700,9342,1)]()}}}catch(Nj@jp@g){}~eak;case Wt:var ~witch(0W]0:var~eak;case 0:W" ascii
    $s15 = "~;return ~;breW}~;switch(~W_@~@omo@l@q~:if(3===~bp@l@q()~){}Wq~Wh@~){case ~(Wh~()Wq~)Wq@~@i@gcIj~;;Wq~rzTxhxI~q@krudm~Wl;~@sxE@m" ascii
    $s16 = "ozW@~)W<~W>0:~W;1~1,6064,7269,71~}WUvar ~2680,9105,165~)+qM@m@tjtN((~W@2~;break;case ~=@zT@rk@t(\"0~[@zT@rk@t(\"0~)WF~@n@sr@mN@r" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}