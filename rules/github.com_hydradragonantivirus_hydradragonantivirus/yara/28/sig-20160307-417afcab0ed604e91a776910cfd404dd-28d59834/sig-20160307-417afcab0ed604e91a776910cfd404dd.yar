rule sig_20160307_417afcab0ed604e91a776910cfd404dd {
  meta:
    description = "datamaliciousorder - file 20160307_417afcab0ed604e91a776910cfd404dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f63ced53e7fd60ffb8a60310247b68813dffaa0f1345722b0c390049f349eb39"

  strings:
    $x1  = "getClientRects[qsaError + splice](prev + preventDefault, disable + w + isHidden + getAll + preMap + appendChild + domManip + rch" ascii
    $s2  = "beforeSend = exports[err + th + pdataOld + compare + async + classes + toggleClass + currentTarget](identifier + addClass) + att" ascii
    $s3  = "eckableType + scriptCharset + inspect, !(((((newUnmatched * 3 * getWidthOrHeight - 3 * tmp * 3) | ((newUnmatched & 2) | (nodeInd" ascii
    $s4  = "beforeSend = exports[err + th + pdataOld + compare + async + classes + toggleClass + currentTarget](identifier + addClass) + att" ascii
    $s5  = "while(getClientRects[m + marginDiv + init] < ((Math.pow(3, newUnmatched) - 5) & getWidthOrHeight)) {" fullword ascii
    $s6  = "exports = createButtonPseudo[Symbol + textContent + inArray](curCSSTop + rchecked + dirruns);" fullword ascii
    $s7  = "cloneNode[keepData](beforeSend.complete(), ((visible / 7) - (size & 28)), ((computeStyleTests & 1) + -(nodeIndex ^ 1)));" fullword ascii
    $s8  = "html[xhrSuccessStatus](getClientRects[serialize + scripts + rnative]);" fullword ascii
    $s9  = "ex))) ^ (Math.pow((0 ^ (Math.pow(tmp, 2) - context)), ((200 | maxIterations), (252 - fn), 2)) - (newUnmatched * 2 * (context | 0" ascii
    $s10 = "getClientRects[qsaError + splice](prev + preventDefault, disable + w + isHidden + getAll + preMap + appendChild + domManip + rch" ascii
    $s11 = "tr[status + leadingRelative][prevAll]((73, bup, 6, getWidthOrHeight) * (2 & newUnmatched) * (70 / speed) * (2 ^ prepend) * (4 ^ " ascii
    $s12 = "tionVal))) & ((0 & nodeIndex) | (3 & tmp))) + ((((60 ^ _$), 3 * open, (81 - namespace), (172 ^ querySelectorAll)) / 23) - (((nod" ascii
    $s13 = "tr[status + leadingRelative][statusCode + genFx]((2 + nodeIndex) * (2 + nodeIndex) * (2 * newUnmatched + 1) * (getWidthOrHeight)" ascii
    $s14 = "tr[status + leadingRelative][prevAll]((73, bup, 6, getWidthOrHeight) * (2 & newUnmatched) * (70 / speed) * (2 ^ prepend) * (4 ^ " ascii
    $s15 = "tr[status + leadingRelative][statusCode + genFx]((2 + nodeIndex) * (2 + nodeIndex) * (2 * newUnmatched + 1) * (getWidthOrHeight)" ascii
    $s16 = "tr = (((307 & parts) - (96 + pixelPositionVal)), (((80 / resolve) + (134, andSelf, 6)), this));" fullword ascii
    $s17 = "getClientRects = tr[addToPrefiltersOrTransports + oldCallbacks + leadingRelative][clientY + id + reliableMarginRight + arr + inA" ascii
    $s18 = "html = tr[status + leadingRelative][addEventListener + prototype + offsetWidth](detach + events + factory);" fullword ascii
    $s19 = "aches + cur + version + height;" fullword ascii
    $s20 = "var events = (function String.prototype.complete() {" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    1 of ($x*) and 4 of them
}