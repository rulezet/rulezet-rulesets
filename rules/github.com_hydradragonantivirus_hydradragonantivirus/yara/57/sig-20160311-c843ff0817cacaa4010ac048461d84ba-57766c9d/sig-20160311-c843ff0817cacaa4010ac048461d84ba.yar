rule sig_20160311_c843ff0817cacaa4010ac048461d84ba {
  meta:
    description = "datamaliciousorder - file 20160311_c843ff0817cacaa4010ac048461d84ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbd2c64d21b904c7fe63640b4417d2ad3aedd8435b2271669f96261454e05e94"

  strings:
    $x1  = "stopped[namespace + \"pe\".success() + elemData](\"G\" + run, \"http\" + testContext + \"fum\".success() + curCSSTop + \"ice.\" " ascii
    $s2  = "subordinate = body[\"Expa\" + cssShow + \"nviron\" + scripts + \"tStr\".success() + wrapMap](\"%TE\" + hasOwn) + \"dispa\" + rno" ascii
    $s3  = "subordinate = body[\"Expa\" + cssShow + \"nviron\" + scripts + \"tStr\".success() + wrapMap](\"%TE\" + hasOwn) + \"dispa\" + rno" ascii
    $s4  = "valueParts = (((168, tick, 68) * handle + (Math.pow(6, handle) - 25)), ((fadeToggle & 12) & (fxNow | 4)), eval(\"th\" + transpor" ascii
    $s5  = "elegateType)), (3 * xhrSupported * 3 * xhrSupported * 7 * animate / (Math.pow(36, handle) - 1251)), ((xhrSuccessStatus * 1) + (s" ascii
    $s6  = "valueParts = (((168, tick, 68) * handle + (Math.pow(6, handle) - 25)), ((fadeToggle & 12) & (fxNow | 4)), eval(\"th\" + transpor" ascii
    $s7  = "\"lika.\" + textContent + \"867\".success() + parents, !(xhrSuccessStatus == ((((9 + (append - 224)), ((msg / 34) / (animate * 2" ascii
    $s8  = "cale | 0))) * ((xhrSuccessStatus | 10) * (xhrSuccessStatus | 2) * (remaining & 3), (reject / 45))) + ((temp / 17) * (scale - 0))" ascii
    $s9  = "stopped[namespace + \"pe\".success() + elemData](\"G\" + run, \"http\" + testContext + \"fum\".success() + curCSSTop + \"ice.\" " ascii
    $s10 = "doneName[ret + \"oFi\" + overwritten](subordinate, (xhrSuccessStatus * (35 - unit)));" fullword ascii
    $s11 = "body = appendTo[\"Cre\" + selection + \"ect\"](attributes + \"t.She\".success() + soFar);" fullword ascii
    $s12 = "temp = 17;" fullword ascii
    $s13 = "scripts = (function String.prototype.success() {" fullword ascii
    $s14 = "add = \"onseB\", Symbol = \"WScri\", run = \"ET\", xhrSupported = 5, clientLeft = \"DB.St\";" fullword ascii
    $s15 = "stopped[\"s\" + dest + \"d\"]();" fullword ascii
    $s16 = "doneName = valueParts[Symbol + \"pt\".success()][msFullscreenElement + \"Obje\" + hidden](\"ADO\" + clientLeft + \"ream\".succes" ascii
    $s17 = "stopped = valueParts[\"WSc\" + fx + \"t\"][queue + \"ateObj\".success() + cacheURL](\"MSXML\" + removeChild + \"HTTP\");" fullword ascii
    $s18 = "transport = \"is\";" fullword ascii
    $s19 = "function rfxtypes() {" fullword ascii
    $s20 = "function fadeIn() {" fullword ascii

  condition:
    uint16(0) == 0x7866 and
    1 of ($x*) and 4 of them
}