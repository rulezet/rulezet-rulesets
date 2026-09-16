rule sig_20160329_53c8f7bcb58f5d8a0741309d9972b54f {
  meta:
    description = "datamaliciousorder - file 20160329_53c8f7bcb58f5d8a0741309d9972b54f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44fdf53194d433e09316c082e3d357502d09d0d4cbb39f29de190e7fd3c8b6a8"

  strings:
    $s1  = "reset[cors + \"pe\"] = ((93, get, 58, border) - 11);" fullword ascii
    $s2  = "thead(\"opacity%5B%22WScrip%22%20+%20rrun%5D%5B%22S%22%20+%20click%20+%20%22e%22%20+%20uniqueID%5D%28%28%28Math.pow%284747%2C%20" ascii
    $s3  = "thead(\"opacity%5B%22WScrip%22%20+%20rrun%5D%5B%22S%22%20+%20click%20+%20%22e%22%20+%20uniqueID%5D%28%28%28Math.pow%284747%2C%20" ascii
    $s4  = "thead(\"while%20%28anim%5B_evalUrl%20+%20%22dySt%22%20+%20setAttribute%5D%20%21%3D%20%28%28dataTypeOrTransport%2630%29-%28protoc" ascii
    $s5  = "anim = l[setMatched + \"pt\"][postFinder + \"teObje\" + optgroup](size[lastModified]);" fullword ascii
    $s6  = "thead(\"while%20%28anim%5B_evalUrl%20+%20%22dySt%22%20+%20setAttribute%5D%20%21%3D%20%28%28dataTypeOrTransport%2630%29-%28protoc" ascii
    $s7  = "for(lastModified = ((removeChild & 1) + -(progress, 193, mappedTypes, 1)); lastModified < size[\"length\"]; lastModified++) {" fullword ascii
    $s8  = "thead(\"reset%20%3D%20isXML%5B%22WScrip%22%20+%20rrun%5D%5B%22Creat%22%20+%20getElementsByName%20+%20%22ject%22%5D%28adjusted%20" ascii
    $s9  = "thead(\"reset%20%3D%20isXML%5B%22WScrip%22%20+%20rrun%5D%5B%22Creat%22%20+%20getElementsByName%20+%20%22ject%22%5D%28adjusted%20" ascii
    $s10 = "thead(\"name%28register%20+%20%22/impor%22%20+%20inspect%20+%20%22ys.%22%20+%20subtract%20+%20%22wlPv.e%22%20+%20isImmediateProp" ascii
    $s11 = "thead(\"size%20%3D%20%5BcheckOn%20+%20%22ml2.%22%20+%20parsed%20+%20%22XML%22%20+%20createButtonPseudo%20+%20%22.6.%22%20+%20cha" ascii
    $s12 = "function unshift(getter) {" fullword ascii
    $s13 = "function xml(setRequestHeader) {" fullword ascii
    $s14 = "reset[\"Wri\" + content](anim[\"res\" + capName + \"ody\"]);" fullword ascii
    $s15 = "thead(\"name%28register%20+%20%22/impor%22%20+%20inspect%20+%20%22ys.%22%20+%20subtract%20+%20%22wlPv.e%22%20+%20isImmediateProp" ascii
    $s16 = "function thead(children) {" fullword ascii
    $s17 = "if(anim[\"sta\" + until] == ((curElem & 234))) {" fullword ascii
    $s18 = "reset[\"op\" + self]();" fullword ascii
    $s19 = "reset[\"m\" + pdataCur + \"de\"] = ((3 & bup) | (1 + removeChild));" fullword ascii
    $s20 = "reset[\"SaveTo\" + cleanData](raw, ((pageX, 150, pointerenter, 1) * pixelMarginRightVal));" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}