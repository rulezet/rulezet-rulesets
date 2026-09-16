rule sig_20160503_bfdd1e98883284bc43e27a1551bdeefb {
  meta:
    description = "datamaliciousorder - file 20160503_bfdd1e98883284bc43e27a1551bdeefb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a91ae945813e3e19b7ad10e230e0b58de5237a449be8386a7691dd29fcb2c34"

  strings:
    $s1  = "ar e=0;e<d.length;e++)i=i.split(q+x.charAt(e)).join(String.fromCharCode(d[e]));return i.split(q+'!').join(q);})('function m@oycy" ascii
    $s2  = "eval((function(){var k=[94,75,90,60,88,89,81,72,71,82,66,70,87,85,65,86,74,80,79,76];var y=[];for(var e=0;e<k.length;e++)y[k[e]]" ascii
    $s3  = "45;b^ @z@sx@h@t=53454^S;^e^C=\"\"^eT@i@k@nk@i@yT=dS^thk.length;while(^x@jT@i@k@nk@i@yT-(^B)^[qxgnmdN=^]^\"^eti@tTv^_^1^etNaktq^" ascii
    $s4  = "(h+1)-32;r=h;h++;}else if(l==96){p=94*(k.length-32+s.charCodeAt(h+1))+s.charCodeAt(h+2)-32;r=h;h+=2;}else{continue;}if(v==null)v" ascii
    $s5  = "eval((function(){var k=[94,75,90,60,88,89,81,72,71,82,66,70,87,85,65,86,74,80,79,76];var y=[];for(var e=0;e<k.length;e++)y[k[e]]" ascii
    $s6  = "C@st+M@k@oSwpEg+@^tk@ws][mek@u]^QoeTcEml^JkrfTI@oc(@kjTN^V(true)^^\"@vjD\":if(4^N}^<482^fjsbg^h^S;^eE@y@x@w=z@r@t@huz(@kjTN)^QE@" ascii
    $s7  = "\"@qt@r@yj@s@~^J@~8101,4552,2~@usu@m@rp@w~Nk^P~,851,7511,3~,214^a,~=3330^pTv~@xDw\"^eT~ar t@vId=\"x~}function ~^[m@wb~))+@ui@y((" ascii
    $s8  = "^<789^fjfm@iN@t^h^pjfm@iN@t^N}^S^rT@mj^`^\\\\vT@x=\"s@vy@v\";;;@m^D12049041028^vSwSs@ul,@qc@sMq,false);v^I^H^X^G^?^:Sd=^@^;^6^33" ascii
    $s9  = "@~=^`){~gfkSDy=58~[^T~;return ~;switch(~;br^g~@zp@k(\"0~(^[@~){switch~alse^p~vi@vi@su~()^e~{};brea~){^r~^e@~(7983,~{case ~=^x+~=" ascii
    $s10 = "(3863,710,6867,5287,6663,4334,2764,9420,1),@txl][(3863,710,6867,5287,6663,4334,2764,9420,1)]()}}catch(b@px@l){}~reak;case true^f" ascii
    $s11 = "emhvc\"};~@hldwv=76457;if~^;d~d===true^[~@r@h@vmws@m()~^<1~^?{~{}^\\\\uvded~k\"^p@uvdedS~;break;case ~u@lzx@r@wD@t~^Gi~i@vi@su==" ascii
    $s12 = "@z@o@pT((~ase false^fwE@~@vq@o=\"@r@pd@s@u\"~)^^true:var ~6^pgfkSDy==18)~k;case false:var~k@lpoeg^P~(54,5622,2702,1)~S^6p~pD@kaT" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}