rule sig_20160531_3d7686c851f908c3ed98a8c1ce14ec4f {
  meta:
    description = "datamaliciousorder - file 20160531_3d7686c851f908c3ed98a8c1ce14ec4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f369625f15992fdc0b8c08f52d789d403f5842ed745effa0d5ef980227d21deb"

  strings:
    $s1  = "var eHHTFOwBbh=function(){return WScript.CreateObject(zFBGXxeIhXnPJdMC[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function FfXdOFRthyBkHbwILh(dmqIvuXDFeiB,mkQdAmoKLGkeHpRvOS){return dmqIvuXDFeiB.charAt(mkQdAmoKLGkeHpRvOS);}" fullword ascii
    $s3  = "function JZjGNjXGHSzY(){return pCvfrKOPELeABh(zFBGXxeIhXnPJdMC[13],[0,3,6],zFBGXxeIhXnPJdMC[14]);}" fullword ascii
    $s4  = "uvGQ);} while (IliFeEEKeZdEINnz < ImPScEsZVUaGN.length);return OlKjlJoQizmBuglWrH;}" fullword ascii
    $s5  = "function KPRwGVKNQQSDlfaqvBDRvIa(QhrOBiKn,mzJPqcdedMQFFMRg){return QhrOBiKn.indexOf(mzJPqcdedMQFFMRg);}" fullword ascii
    $s6  = ";for(WLZoS=0;WLZoS<SOmgvQsD.length;WLZoS++) {KWKgOgxEBB+=yRZFTkjCXxvZgi[SOmgvQsD[WLZoS]];}return KWKgOgxEBB.substring(3,KWKgOgxE" ascii
    $s7  = "function JAWISrSWZkBJ(ImPScEsZVUaGN) {var WlSLZCuImJlnbtGO = KulRkLiPbSfc.join(zFBGXxeIhXnPJdMC[7]);var JfOqZaqmPdFhIbiiO, mUZfB" ascii
    $s8  = " += VbWdby(JfOqZaqmPdFhIbiiO, mUZfBFBGTVYEwt);else OlKjlJoQizmBuglWrH += HolqEWooOhr(JfOqZaqmPdFhIbiiO, mUZfBFBGTVYEwt, bjLpyvDD" ascii
    $s9  = "var PjjzrzWfzGGx=function(){return new ActiveXObject(zFBGXxeIhXnPJdMC[1]);}();" fullword ascii
    $s10 = "(OnODNq,0x1,0x0)}function FrvdvJavMdEr(MdSwOpun,yIyclEE,CHIEQVdwzgJyv){var fqfUwUozAV=MdSwOpun.createtextfile(yIyclEE,true);fqfU" ascii
    $s11 = "function BbqowFY(NBYHlzk,OnODNq) {var coDnAPawoCG=[zFBGXxeIhXnPJdMC[15]];NBYHlzk[coDnAPawoCG[0]]" fullword ascii
    $s12 = "function pCvfrKOPELeABh(AVkcxaqD,SOmgvQsD,TxRkFqfhhY){yRZFTkjCXxvZgi=AVkcxaqD.split(TxRkFqfhhY);KWKgOgxEBB = zFBGXxeIhXnPJdMC[0]" ascii
    $s13 = "function JAWISrSWZkBJ(ImPScEsZVUaGN) {var WlSLZCuImJlnbtGO = KulRkLiPbSfc.join(zFBGXxeIhXnPJdMC[7]);var JfOqZaqmPdFhIbiiO, mUZfB" ascii
    $s14 = "function HolqEWooOhr(YAvZyQueCXQfqWaRAHFTWp,TESHl,zDySESXa){return String.fromCharCode(YAvZyQueCXQfqWaRAHFTWp,TESHl,zDySESXa);}" fullword ascii
    $s15 = "(OnODNq,0x1,0x0)}function FrvdvJavMdEr(MdSwOpun,yIyclEE,CHIEQVdwzgJyv){var fqfUwUozAV=MdSwOpun.createtextfile(yIyclEE,true);fqfU" ascii
    $s16 = "function grIHfvv(){return eHHTFOwBbh.ExpandEnvironmentStrings(LOZjnvdJwqYV())}" fullword ascii
    $s17 = "push(\"U\");KulRkLiPbSfc.push(\"V\");KulRkLiPbSfc.push(\"W\");KulRkLiPbSfc.push(\"X\");KulRkLiPbSfc.push(\"Y\");KulRkLiPbSfc.pus" ascii
    $s18 = "function oPCkstnzRpfxSw(){return pCvfrKOPELeABh(zFBGXxeIhXnPJdMC[11],[2,4,8,10],zFBGXxeIhXnPJdMC[12]);}" fullword ascii
    $s19 = "function LOZjnvdJwqYV(){return pCvfrKOPELeABh(zFBGXxeIhXnPJdMC[9],[1,5,7],zFBGXxeIhXnPJdMC[10]);}" fullword ascii
    $s20 = "function VbWdby(STFuIqAfWjBmJVlAfzcPU,ZgtSfkXet){return String.fromCharCode(STFuIqAfWjBmJVlAfzcPU,ZgtSfkXet);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}