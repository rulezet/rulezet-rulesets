rule sig_20160308_5175200d454fd63b59c9c90c85c6e25f {
  meta:
    description = "datamaliciousorder - file 20160308_5175200d454fd63b59c9c90c85c6e25f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69befbf411824c4325841ee5ffa47a3dd022a9f538290765c11b36c247e3858a"

  strings:
    $s1  = "contents = cssPrefixes[curPosition + textContent + j + html](options + isNumeric + ready);" fullword ascii
    $s2  = " href), (24 / origType)) - (83 ^ compiled)), this));" fullword ascii
    $s3  = "cached = \"Cre\", textContent = \"teObj\", forward = \"opt\", returnFalse = \"http:\";" fullword ascii
    $s4  = "cssExpand[rcheckableType](bySet, returnFalse + propFix + expando + flatOptions + hasClass + rhash + cssNormalTransform + valHook" ascii
    $s5  = "overflowX = (2 * (caption | 2) * (disconnectedMatch / 39) * (adjustCSS | 2) * (memory + 8), ((Math.pow((Math.pow(structure, 2) -" ascii
    $s6  = "fn = overflowX[offsetWidth + body][nodeIndex + emptyGet + promise + marginLeft + initialInUnit](setter + attributes + htmlPrefil" ascii
    $s7  = "fn[augmentWidthOrHeight + getter + setOffset + text](PI, ((1 * adjustCSS) & (1 | adjustCSS)));" fullword ascii
    $s8  = "fn = overflowX[offsetWidth + body][nodeIndex + emptyGet + promise + marginLeft + initialInUnit](setter + attributes + htmlPrefil" ascii
    $s9  = "PI = contents[rquickExpr + unquoted + _ + appendChild + parseJSON + prototype](clazz + pos) + forward + risSimple + initialInUni" ascii
    $s10 = "overflowX[offsetWidth + body][queue](((isImmediatePropagationStopped ^ 30870) - (rquery - 5914)));" fullword ascii
    $s11 = ")) | (0 | caption))) * (((7 * adjustCSS * 2 | (divStyle - 17)) - ((Math.pow(startLength, 2) - charCode) / 3 * memory * 2)) ^ ((a" ascii
    $s12 = "overflowX = (2 * (caption | 2) * (disconnectedMatch / 39) * (adjustCSS | 2) * (memory + 8), ((Math.pow((Math.pow(structure, 2) -" ascii
    $s13 = "    overflowX[curOffset + needsContext][configurable + removeChild]((max * 3 * structure * 3, (MAX_NEGATIVE - 40)));" fullword ascii
    $s14 = "what = \"Run\", rhash = \"ejes\", clearCloneStyle = \"n\", marginLeft = \"c\";" fullword ascii
    $s15 = "getter = \"ave\";" fullword ascii
    $s16 = "PI = contents[rquickExpr + unquoted + _ + appendChild + parseJSON + prototype](clazz + pos) + forward + risSimple + initialInUni" ascii
    $s17 = "left = contents;" fullword ascii
    $s18 = "s + callback + suffix + rsibling + elem, !(((((1 + oldfire) + ((1 ^ caption) * (1 + -oldfire))) ^ (((65, caption) / (792 / check" ascii
    $s19 = "percent[initialInUnit + firstChild] = ((ajaxConvert - 43) * (caption ^ 1));" fullword ascii
    $s20 = "djustCSS + 0) | ((oldfire | 1) ^ (global / 24))))) == (((caption & (0 | caption)) | ((0 / destElements) / (3 & max))) | (((18 - " ascii

  condition:
    uint16(0) == 0x414d and
    8 of them
}