rule sig_20160503_0e1e79e73c9f7ce2f390b9fb91f3de9d {
  meta:
    description = "datamaliciousorder - file 20160503_0e1e79e73c9f7ce2f390b9fb91f3de9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e0e2e4ad2ca66505f65a3b37297716d197470dcd03134c7b83aefbeb09b2a9a"

  strings:
    $s1  = "@z@xS\")=F`){if(i@l@x@lD@nr(\"ye@h\",Fw,\"r@r@qe\",true)==0F^E@zb=73195}}FpfyMc@xS=([(2350,8469,3033,7352,9522,7773,4665,0),@wSc" ascii
    $s2  = "ar i=0;i<e.length;i++)u=u.split(o+a.charAt(i)).join(String.fromCharCode(e[i]));return u.split(o+'!').join(o);})('function @wgCdq" ascii
    $s3  = "eval((function(){var d=[70,72,88,71,82,66,65,75,85,79,74,89,94,86,60,81,87,80,90,76];var h=[];for(var i=0;i<d.length;i++)h[d[i]]" ascii
    $s4  = "(f+1)-32;j=f;f++;}else if(q==96){k=94*(d.length-32+p.charCodeAt(f+1))+p.charCodeAt(f+2)-32;j=f;f+=2;}else{continue;}if(r==null)r" ascii
    $s5  = "eval((function(){var d=[70,72,88,71,82,66,65,75,85,79,74,89,94,86,60,81,87,80,90,76];var h=[];for(var i=0;i<d.length;i++)h[d[i]]" ascii
    $s6  = "@l(\"0~[@pyI@l(\"0~=(2093H*~\"FL~FY;;~NaDthdtn10~Fk4){c~FS@~\"FS~eceq@gM()~h@jcq@j()~pT@o@kd((~)FT~=Fe+(~;return ~;sFk~(FZ~)Fa\"" ascii
    $s7  = "vgTg@q===0F^u@q@vza@w@q=\"@kDl@oa\"}FYif(2==708FZr@jl=\"sikcd@g\"}F_oxbS=\"\"FpE@m@r@x@h=@v@g@wtki@iz.length;while(Fe@uE@m@r@x@h" ascii
    $s8  = "801,1125,5265~case trueFs~p@m@q=3805;br~;Fz;case ~))+FP~FB8~8,7307,3244,~;sFK~FD@~){}FY~41,7236,754~CuN@jj@p@m(~}function ~=@pyI" ascii
    $s9  = "Fe);~;Fz};~F^@~(Fb~1439,58~F`;~){H ~Fp@~=Fw~{case ~)Fp~\"Fs~0Fs~rur@ph~=Fv~,8415,~k@ypbt~{};var~Fv;~witch(~)H#@~@nz@x(~glhsje~Fw" ascii
    $s10 = "7,1697H.9,1),xvp][(5682,3305,7436,1625,587,6086,7039,7948,9530,3347,1697H.9,1)]()}}catch(@nrM@pn@j){}~F;0:var @~eak;case Fovar ~" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}