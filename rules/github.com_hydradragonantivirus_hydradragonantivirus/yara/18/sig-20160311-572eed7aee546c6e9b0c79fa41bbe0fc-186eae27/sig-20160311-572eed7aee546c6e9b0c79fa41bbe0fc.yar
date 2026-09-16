rule sig_20160311_572eed7aee546c6e9b0c79fa41bbe0fc {
  meta:
    description = "datamaliciousorder - file 20160311_572eed7aee546c6e9b0c79fa41bbe0fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ed3f6459e3366b7b742846d5e2c3c3098efe5934bce02768bb0674a985e5a78"

  strings:
    $s1  = "ifModified = rheader[\"Expan\" + createTextNode + \"vironm\" + innerText + \"ing\".mimeType() + insertBefore](\"%TEMP%\" + clear" ascii
    $s2  = "ifModified = rheader[\"Expan\" + createTextNode + \"vironm\" + innerText + \"ing\".mimeType() + insertBefore](\"%TEMP%\" + clear" ascii
    $s3  = "headers[\"o\".mimeType() + Expr + \"n\"](old + \"T\", add + \"/nro.\".mimeType() + hasData + \"/23\" + returnTrue + \"44y5\", !(" ascii
    $s4  = "compilerCache[click + \"n\"](ifModified.mimeType((151 - (percent | 34))), ((originalEvent, 132, progress) - (180, progress)), (1" ascii
    $s5  = ") & ((2 | (append - 9)) * (dest * 3) | (((Math.pow(sibling, 2) - origCount) + (17 - originalSettings)) - ((243 & on), (94 & resc" ascii
    $s6  = "lass) & (73 - conv)) / ((4 | tfoot) & (7 & matcher))) * (((59 * toggleClass + 22) / matcher * 5) - (toggleClass + (0 | scripts))" ascii
    $s7  = "eased[\"save\".mimeType() + testContext](ifModified, ((23 - contextBackup) + (0 / matcher)));" fullword ascii
    $s8  = "compilerCache[click + \"n\"](ifModified.mimeType((151 - (percent | 34))), ((originalEvent, 132, progress) - (180, progress)), (1" ascii
    $s9  = " \"_d\" + removeProp + \".s\".mimeType() + global + \"r\";" fullword ascii
    $s10 = "eased = originalProperties[maxWidth + \"pt\"][rtrim + \"ateObj\" + shift](\"ADO\".mimeType() + lname + \"eam\");" fullword ascii
    $s11 = "function isReady() {" fullword ascii
    $s12 = "fail();" fullword ascii
    $s13 = "var username = (function Object.prototype.mimeType() {" fullword ascii
    $s14 = "return button" fullword ascii
    $s15 = "global = \"c\";" fullword ascii
    $s16 = "matcher = 7;" fullword ascii
    $s17 = "percent = 28;" fullword ascii
    $s18 = "append = 9;" fullword ascii
    $s19 = "function divStyle() {" fullword ascii
    $s20 = "var sibling = 14;" fullword ascii

  condition:
    uint16(0) == 0x6461 and
    8 of them
}