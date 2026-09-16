rule sig_20160503_fb08d8738257259630ec6158e9253a9f {
  meta:
    description = "datamaliciousorder - file 20160503_fb08d8738257259630ec6158e9253a9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fd1e10aea03ff45df82143733cc26321cad65333a8730aba2dcf9ac619e52cb"

  strings:
    $s1  = "eval((function(){var i=[76,66,81,70,71,60,65,75,74,94,80,87,90,88,79,89,85,82,86,72];var w=[];for(var x=0;x<i.length;x++)w[i[x]]" ascii
    $s2  = "ar x=0;x<m.length;x++)q=q.split(v+b.charAt(x)).join(String.fromCharCode(m[x]));return q.split(v+'!').join(v);})('function @k@odx" ascii
    $s3  = "(j+1)-32;s=j;j++;}else if(a==96){d=94*(i.length-32+r.charCodeAt(j+1))+r.charCodeAt(j+2)-32;s=j;j+=2;}else{continue;}if(f==null)f" ascii
    $s4  = "@xj@h@q\"LiMn@ko@qLnLP;LKffuq@zyo@zLDC@qylm@i(iazxpq@g,y@r@kpLajdwu=iazxpq@g[y@hdiji@i()](y@r@kpLbl@ytgjLnLhh@wy=\"@jlyh@w@nC\";" ascii
    $s5  = "~(6708,818,77~LD@~)LI(~break}Lh~@w@nt@mzzqx~)+@LW~se trueLu~}function ~u@gNa@km()~===1La~\"LK~}LQ~)+@hSbur(~=@qfEl(N@~;return ~=" ascii
    $s6  = "eval((function(){var i=[76,66,81,70,71,60,65,75,74,94,80,87,90,88,79,89,85,82,86,72];var w=[];for(var x=0;x<i.length;x++)w[i[x]]" ascii
    $s7  = "thsc){if(E@ym==1){LHTNsL]1LuL_L:Spl@g@nh=\"@rvsN@y@w\"};brL-LzgEvCd=\"@yCch\"L;1Li@gqcsmy@n=88305;break;L3@k@qE=\"taqxdla\"LPif(" ascii
    $s8  = "E(uiy@jNgzh){switch(290L]\"@gg@yzo@nS\"LisfwC@t=68532LvsfwC@tLTLa@yM@usC=20165L6732Liukl@m@z@ux=\"@o@sdh@w\";break;L3qTlx@q=LSqT" ascii
    $s9  = "@m@xiLjzbMx@vk===\"@t@j@z@wp@x@t\"L+Lk @qac=68143;L@zo@s=\"NCIueIgLjzo@s==120LOLR=\"\"LhhD@rvnf=N@zxs.length;while(LA@lhD@rvnf-L" ascii
    $s10 = "()}};@k@odx(\"vcNld@r\");@h@k@vky@qq(true,true)}catch(@i@kfw){}~3,4329,3465,2198,0)~L$2~2){}Lv3===188){};~L%\"~Lje@q@z@wrNg==8~@" ascii
    $s11 = "mDfDd@mDLJL/LbNDjE@v=\"EsNd\"LQ301){caLC2===\"IcM@z\"Las@w@tgguv=8961L6304Lu6L:d@tiLnL634Lk @oy@x@iTn=80880;break;L3lS@m=\"@n@y@" ascii
    $s12 = "rNg=\"oal@smmg~L)3~3523,4538,5172,1)~L,7~7,8452,2819,290,~;cT@x@ieLN~){L6~1,6902,8683,557~eak;case Ll:~63,6146,9526,2)~zxs,LA~sw" ascii
    $s13 = "phd(\"0~LZ@~[bphd(\"0~){}Lh~;break};~;switch(~C@i@hgTE~trueLv~==Lc~{Lze@q~(1436,81~oxrtpbx(~LY@~(Lb~(La~Lb@~Lc;~){case ~Sl@jq10~" ascii
    $s14 = "tch(1L]~34,3429,7642,3)~y@ulb@vLN~case trueLi~=LA+(~Ls5===0){};~}L;~)LB(~(5766,1298,52~LJzxs,~==trueLa~;break;case ~z@o@x@oeDx()" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}