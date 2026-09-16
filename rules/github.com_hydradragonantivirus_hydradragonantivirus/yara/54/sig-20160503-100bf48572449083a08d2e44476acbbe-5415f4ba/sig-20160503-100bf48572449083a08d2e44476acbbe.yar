rule sig_20160503_100bf48572449083a08d2e44476acbbe {
  meta:
    description = "datamaliciousorder - file 20160503_100bf48572449083a08d2e44476acbbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd29f07bdc6772588147a6c482f9528220ab8abf8d61d2465328dbf7f476c08d"

  strings:
    $s1  = "ar k=0;k<c.length;k++)z=z.split(r+d.charAt(k)).join(String.fromCharCode(c[k]));return z.split(r+'!').join(r);})('function IS@o@Q" ascii
    $s2  = "eval((function(){var e=[86,81,94,76,60,79,75,66,80,85,88,90,71,74,89,70,72,82,65,87];var u=[];for(var k=0;k<e.length;k++)u[e[k]]" ascii
    $s3  = "N@qVcif(@yzjN@qVVVzd@l@vg=\"jb@n@m@xp\"};break;V9@lmI=\"a@vwjgxaVllmI==0VdwgI@u@h@y=\"fljrj\"}VbVJmsiSeI@v(@h@niNVdbgp@z@p@sy=pa" ascii
    $s4  = "g=\"@mod@mw@z@nVlxszbg==\"Sv@yS@lw\"){}V@t@pduNC=\"cgb@ntzVQVu}try{if(Dl@v@j(0)==0){IS@o@Q+q@o(Vu)}V{j@nzc(true,\"I@m@yen@wx\")=" ascii
    $s5  = "V\"Veunk=\"ih@z@znkk\"Vellx=@unk.lengthVqVA=V\"Vqw@rgVUw@rg==VG@nmr@nww=52766}VeVH=\"\"VqD@x@gN=Q4dg@jpd.length;while(VA@kD@x@gN" ascii
    $s6  = "(l+1)-32;s=l;l++;}else if(f==96){i=94*(e.length-32+v.charCodeAt(l+1))+v.charCodeAt(l+2)-32;s=l;l+=2;}else{continue;}if(y==null)y" ascii
    $s7  = "Xo@y@jIVCxQ,@ulo@z(sh@rk@x@rQ/){switch(3){V9D@ovS@p=\"@g@uo@uVvD@ovS@p=VsV21Q(4===332VdfDt@uhC=44985}V;@r@yofeVfcdnmQ*q=\"@wyu@r" ascii
    $s8  = "@nwwVs;break;V9rE@hmv@u=\"@rN@y@qVvrE@hmv@u===0){}V@@z@g@vx=65539Vez@z@wrx@y@o=\"@p@u@wSo@tb\";;VXpMqwVJSdNQ$V]@vpfMmexVE0102803" ascii
    $s9  = "eval((function(){var e=[86,81,94,76,60,79,75,66,80,85,88,90,71,74,89,70,72,82,65,87];var u=[];for(var k=0;k<e.length;k++)u[e[k]]" ascii
    $s10 = "turn ~;switch(~Ev@v@l()~){Vj~eV_~(Vd~(Vg~){case ~=@sD@y(~)+@Q6~;break}~Vh;~){Vz~Vq@~\"Vr~)Vq~=Vu~050\")]~if(1==~;;;var~Vv@~s@rbq" ascii
    $s11 = "6145,5499,1)]()}}else {Vzm@vb@g@w=\"@qi@nw\"}}catch(Tfyvdj@g){}~V&r~rueVdkyx=true};~(2828,8516,6390,0)~=@oSqe(Q4dg@jpd,~=false;b" ascii
    $s12 = "D@zhbN@x~@mj@o@r@mkI~}function ~)+@Vp(~l@gp@q@p()~@rCfvx@x()~reak;case ~tqS@qg@h10~\"}Vb;~\"VX~)VX~)Va(~)VY~Vs;if(~=Vh){~Vd@j@~;" ascii
    $s13 = ",~VY2){case ~V6@~@ugy@zT\"Vb;~){};bVN~mr@zVF~VVvar bz~=VA+(~7Vri@pag=\"zb~rueVrEpn@mIr~@gc@wx@u=66732}~case trueVr~VA);~;bVN\"~(" ascii
    $s14 = "rff=53243;break;V9@mfx@r=60104V{@mfx@r===1VdCakfd@t=\"I@uNgqcyVP;;VI=@nzerrv(VI,tqS@qg@hVgD@nw@x@pb@t=zSj@n@p@lV^t@w@pr@qM=Strin" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}