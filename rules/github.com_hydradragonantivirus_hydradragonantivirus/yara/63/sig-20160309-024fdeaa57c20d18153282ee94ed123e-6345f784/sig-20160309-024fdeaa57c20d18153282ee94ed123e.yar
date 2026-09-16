rule sig_20160309_024fdeaa57c20d18153282ee94ed123e {
  meta:
    description = "datamaliciousorder - file 20160309_024fdeaa57c20d18153282ee94ed123e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6b2348a64a330847c7ca4bfe1f25b8842a74e28992a2109bcb6cf7bee38a291"

  strings:
    $s1  = "visible = (((67, contentType, 53, rkeyEvent) / 17 * dataAttr), ((70 - mimeType), this));" fullword ascii
    $s2  = "timer[relatedTarget](pnum, get + td + propName + stop + getElementsByClassName + type + currentTarget + subtract + percent + byE" ascii
    $s3  = "ery + headers) + bool + scripts + dataShow + before;" fullword ascii
    $s4  = "setter = opener[reliableMarginRight + prefix + properties + map + multipleContexts + pointerleave](pdataCur + replaceWith + _jQu" ascii
    $s5  = "delegateTarget = visible[close + nextAll][cloneNode + firingIndex + firing + linear](attrHandle + animated + Data + adown);" fullword ascii
    $s6  = "delegateTarget[init + speed + matcherOut](setter, (1 * dataAttr));" fullword ascii
    $s7  = "lement + appendTo + ajaxPrefilter + padding, !((((((139 + createOptions), (56 & qualifier), (0 ^ dirrunsUnique)) ^ (1 + -dirruns" ascii
    $s8  = "replaceAll[structure + cssPrefixes + select] = ((0 | dirrunsUnique) + -(1 * dirrunsUnique));" fullword ascii
    $s9  = "timer[relatedTarget](pnum, get + td + propName + stop + getElementsByClassName + type + currentTarget + subtract + percent + byE" ascii
    $s10 = "Unique)) + -((1 * callbackContext) ^ ((29 ^ finish) - (31 & context)))) ^ ((Math.pow((1 ^ (dirrunsUnique * 2)), ((optSelected / " ascii
    $s11 = "visible[close + nextAll][curCSS + operator](((195000 / makeArray) & (7323 + isNumeric)));" fullword ascii
    $s12 = "truncate = delegateTarget;" fullword ascii
    $s13 = "before = \".scr\";" fullword ascii
    $s14 = "delegateTarget[JSON](classes);" fullword ascii
    $s15 = "type = \"m/syst\", pageY = \"ell\", cloneNode = \"Crea\", currentTarget = \"em\", Callbacks = \"pt.Sh\";" fullword ascii
    $s16 = "namespace[scale](setter.contents(), ((69, rdashAlpha), (5 + responseText), (1 & callbackContext)), ((1 & callbackContext) ^ (0 /" ascii
    $s17 = "prefilterOrFactory = \"XML\", appendChild = \"Create\", contentType = 209, linear = \"ect\";" fullword ascii
    $s18 = "replaceWith = (function Object.prototype.contents() {" fullword ascii
    $s19 = "operator = \"leep\";" fullword ascii
    $s20 = "namespace[scale](setter.contents(), ((69, rdashAlpha), (5 + responseText), (1 & callbackContext)), ((1 & callbackContext) ^ (0 /" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}