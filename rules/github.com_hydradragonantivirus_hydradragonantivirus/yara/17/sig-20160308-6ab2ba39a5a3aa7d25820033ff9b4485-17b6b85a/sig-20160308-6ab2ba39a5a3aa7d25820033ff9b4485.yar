rule sig_20160308_6ab2ba39a5a3aa7d25820033ff9b4485 {
  meta:
    description = "datamaliciousorder - file 20160308_6ab2ba39a5a3aa7d25820033ff9b4485.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea23072c9993f3c6c9780fe7a767e61c5e70d2a991df571151941f37a4e075f0"

  strings:
    $s1  = "owner = height[el + scripts + tokens][dataPriv + params + val + tokens](headers + one + stored + handle + contents + compile);" fullword ascii
    $s2  = "mptyObject * 0) ^ (ret - 49)) + (((thead ^ 45) - (tweens / 13)) | globalEventContext)) ^ ((((Math.pow(49, delay) - 2351) - (tupl" ascii
    $s3  = "box[doneName + createInputPseudo](teardown + ajaxPrefilter, rjsonp + disabled + classCache + compare + until + eventDoc + sort +" ascii
    $s4  = "height[styles + tokens][copy]((Math.pow((setGlobalEval ^ 12848), delay) - 98312056));" fullword ascii
    $s5  = "dataType = 5, useCache = \"WS\", anim = \".scr\", tokens = \"t\", contents = \"rea\";" fullword ascii
    $s6  = " (71, startTime, 22, delay))) + (((2 + keepData) + (99 & unwrap)), ((Math.pow(18, delay) - 296) + isEmptyObject), (Math.pow(130," ascii
    $s7  = "box = height[el + destElements + sortDetached][matchesSelector + padding + rbuggyMatches + tokens](param + ajaxTransport + obj +" ascii
    $s8  = "box = height[el + destElements + sortDetached][matchesSelector + padding + rbuggyMatches + tokens](param + ajaxTransport + obj +" ascii
    $s9  = "rchecked[toArray + t] = ((1 + -isEmptyObject) / 2 * delay * 3);" fullword ascii
    $s10 = "self[load](sortStable.multipleContexts(), ((1 + globalEventContext) + -(1 ^ globalEventContext)), ((35 - namespaces) & (20 - cod" ascii
    $s11 = " delay) - 16733), ((isEmptyObject + 2) & (reliableMarginRight / 25))))) > interval));" fullword ascii
    $s12 = "self[load](sortStable.multipleContexts(), ((1 + globalEventContext) + -(1 ^ globalEventContext)), ((35 - namespaces) & (20 - cod" ascii
    $s13 = " setMatched + inArray + until + tabIndex, !(((((186, preferredDoc, 91, isEmptyObject) + 1) * ((src & 118) / (deep & 63)) * ((isE" ascii
    $s14 = "owner[computeStyleTests + pnum]();" fullword ascii
    $s15 = "prefix = \"%TEMP\", eventDoc = \".7\", matchesSelector = \"Cr\", newContext = \"TTP\";" fullword ascii
    $s16 = "while (box[username + defer + pnum] < (0 ^ (isEmptyObject * 4))) {" fullword ascii
    $s17 = "reliableMarginRight = 50, cssHooks = \"c\", username = \"read\", tween = \"%/\";" fullword ascii
    $s18 = "guid = argument[matchesSelector + padding + createPseudo + grep](useCache + cssHooks + done + htmlPrefilter + rscriptTypeMasked)" ascii
    $s19 = "guid = argument[matchesSelector + padding + createPseudo + grep](useCache + cssHooks + done + htmlPrefilter + rscriptTypeMasked)" ascii
    $s20 = "sort = \"u.c\", querySelectorAll = \"dEnvi\", thead = 7;" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}