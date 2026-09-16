rule sig_20160313_2ac53062c21cff384ab758fd2edf6d71 {
  meta:
    description = "datamaliciousorder - file 20160313_2ac53062c21cff384ab758fd2edf6d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c94bc6a70a73c013cfc81844a81ac8897899765bddd9a04eb59ba44fb6662b11"

  strings:
    $s1  = "classNames[\"op\" + accepts + \"n\"](wrapMap + \"ET\", step + \"/ohel\" + getResponseHeader + \"q.c\" + tfoot + \".ex\" + accept" ascii
    $s2  = "+ completeDeferred) & (108 - eq)) / (Math.pow(12, ajaxHandleResponses) - 131)) & ((risSimple) + (46 - rneedsContext))) * ((Math." ascii
    $s3  = ") - (useCache & 60922))) / (((disabled & 7) & (ajaxHandleResponses + 4)))) + (((Math.pow(emptyGet, 2) - minWidth) + 3) * (risSim" ascii
    $s4  = "rtypenamespace = rquery[filter + \"ndE\" + selection + \"onment\" + unshift + \"ing\" + response](\"%TEMP\" + optDisabled) + \"_" ascii
    $s5  = "rtypenamespace = rquery[filter + \"ndE\" + selection + \"onment\" + unshift + \"ing\" + response](\"%TEMP\" + optDisabled) + \"_" ascii
    $s6  = "function relatedTarget() {" fullword ascii
    $s7  = "completeDeferred = 24, optDisabled = \"%/\", arg = 728, classes = 14336, getResponseHeader = \"loguyq\";" fullword ascii
    $s8  = "subtract[\"o\" + els + \"e\" + holdReady]();" fullword ascii
    $s9  = "classNames[\"op\" + accepts + \"n\"](wrapMap + \"ET\", step + \"/ohel\" + getResponseHeader + \"q.c\" + tfoot + \".ex\" + accept" ascii
    $s10 = "left = \"ody\", opacity = \"WSc\", emptyGet = 44;" fullword ascii
    $s11 = "subtract[\"saveT\" + rclickable](rtypenamespace, ((ajaxHandleResponses) | 0));" fullword ascii
    $s12 = "subtract = this[opacity + \"ript\"][Symbol + \"ateO\" + ajaxPrefilter](\"ADODB.\" + startTime);" fullword ascii
    $s13 = "rquery = swap[\"Cre\" + tuple + \"jec\" + rprotocol](\"WScr\" + rwhitespace + \"hell\");" fullword ascii
    $s14 = "swap = this[\"WScri\" + bubbleType];" fullword ascii
    $s15 = "step = \"http:/\";" fullword ascii
    $s16 = "function compare() {" fullword ascii
    $s17 = "compare();" fullword ascii
    $s18 = "function dest() {" fullword ascii
    $s19 = "function submit() {" fullword ascii
    $s20 = "submit();" fullword ascii

  condition:
    uint16(0) == 0x7277 and
    8 of them
}