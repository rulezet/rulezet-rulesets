rule sig_20160503_1cae3feeed02ffd9c5a5af1f38387882 {
  meta:
    description = "datamaliciousorder - file 20160503_1cae3feeed02ffd9c5a5af1f38387882.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e9b715f45529dc93a0235bd5c0a76722205efcf99b624a36067e4646af2b512"

  strings:
    $s1  = "ar t=0;t<o.length;t++)m=m.split(f+a.charAt(t)).join(String.fromCharCode(o[t]));return m.split(f+'!').join(f);})('function @ry@rl" ascii
    $s2  = "eval((function(){var w=[87,82,66,76,60,94,71,81,90,74,80,85,79,65,75,72,88,70,89,86];var y=[];for(var t=0;t<w.length;t++)y[w[t]]" ascii
    $s3  = ".length;while(Wv@k@wwn@or-W_W72)Wo@gEE@rMk@h=(W%W#W!WtxtI@gCEw@uWjWxW6W3W/Wt@woI@oo@q@yW(xtI@gCEw@u)WtMu@rMM@mW(Wv+W_W72))WtrlEe" ascii
    $s4  = "@idj)WLMNb@p(DfNq@mpWoiS@i=27762WziS@iW^}W`false)W>Wy@mpky=W{W<55Wu mimWMmim==624){};R!W+l@qzWMl@qz=WpW,\"@zt@jn\":WyDw@tCzr=\"@" ascii
    $s5  = "@g~9,7209,665,~}function ~Wkif(~=tdS@nq(\"0~[tdS@nq(\"0~))+Wr(~NfNxqo@w@n~@q@zIfbD()~)Wta@mi~W`1)~W]@~\"W]~==0Wo~wox@m@o()~hN@h@" ascii
    $s6  = "\"r\"WUo@p@g@plWLgWR{Wy@te@ix@m@z=\"C\"WUte@ix@m@zWFy@tNcjNDWgyM@hv@qp=\"@tWVyM@hv@qWHqWf{switch(3Wi120:Wy@ylhN@o=61865W<0:Wy@m@" ascii
    $s7  = "eval((function(){var w=[87,82,66,76,60,94,71,81,90,74,80,85,79,65,75,72,88,70,89,86];var y=[];for(var t=0;t<w.length;t++)y[w[t]]" ascii
    $s8  = "(j+1)-32;n=j;j++;}else if(q==96){p=94*(w.length-32+x.charCodeAt(j+1))+x.charCodeAt(j+2)-32;n=j;j+=2;}else{continue;}if(h==null)h" ascii
    $s9  = "47~R!k;case false:~437,179,1865,9861~W*a~ar iE@vMezCWq~=DCoh(mwnu@pzEd,~W-k~kaoi=W^};v~k;case true:Wy~){W5~aoi=49877Wzit~W31~14," ascii
    $s10 = "@z=\"@w@pgl\"}WT{case W{W|@t@nc==0){};R!W+@xpTyc@q=61544W=p@jS=\"Tukbtzy\"WLmcC@zbWgs@uu@nmzq=[(966R$06,7145,8013,333R$19,6163,9" ascii
    $s11 = "se ~Wm;var ~{case false:~3709,9374,3)~eak}W`~WK3~Dj@wND@v\";if~@r=67974;var~@pWO~))+Wl(~WL@~f@s@ql@qt()~pWL~1,3416,7035~jcw@r@tw" ascii
    $s12 = "w~)W`~,8801,384~ebsgadM10~;return ~==W{){~(3695,96~;switch(~D@obag@y~@hy@zc@z~{case 0:~trueWz~Wp};~pI@xpe()~(Wo~()Wt~){case ~=Wv" ascii
    $s13 = "yCSuWt@vx@i@i=Iia@zWt@gwf@m@i@rb@p=SmlDk[SEd@r()](@vx@i@i)WT{case 1W|4WWrphEE@g=W{};W$Wyc@mT@govrWMc@mT@govr=W^WyECjr@h@y@pWeR!W" ascii
    $s14 = "977,5823,8752,1)]()}}else {@ry@rl(0,W{,W{)};En@nTS(\"y@q@t@o\",165)}catch(n@ymr@tm){}~W#2~2,8195,5660,2359,0)~W%,~,2170,7098,166" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}