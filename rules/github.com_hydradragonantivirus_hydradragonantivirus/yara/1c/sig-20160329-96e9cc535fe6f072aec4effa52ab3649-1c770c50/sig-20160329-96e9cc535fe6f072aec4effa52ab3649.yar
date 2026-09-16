rule sig_20160329_96e9cc535fe6f072aec4effa52ab3649 {
  meta:
    description = "datamaliciousorder - file 20160329_96e9cc535fe6f072aec4effa52ab3649.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce29c6afc4bc4dcf416e87661cb8c5f4a295527c9a53fa7b55430bcea38ca2bc"

  strings:
    $s1  = "   blur(\"marginRight%20%3D%20%5B%22Msxml%22%20+%20hasScripts%20+%20%22erve%22%20+%20rwhitespace%20+%20%22HTT%22%20+%20overrideM" ascii
    $s2  = "arr(_default, responseHeaders, contents);" fullword ascii
    $s3  = "contentDocument[\"m\" + self + \"de\"] = (3 + (capName - 45));" fullword ascii
    $s4  = "      contentDocument[\"Save\" + match + \"ile\"](condense, ((conv / 27) - (pixelMarginRightVal / 18)));" fullword ascii
    $s5  = "      contentDocument[contents](fx[\"res\" + dataUser + \"seBod\" + removeProp]);" fullword ascii
    $s6  = "   blur(\"marginRight%20%3D%20%5B%22Msxml%22%20+%20hasScripts%20+%20%22erve%22%20+%20rwhitespace%20+%20%22HTT%22%20+%20overrideM" ascii
    $s7  = "      unique[progress + \"ipt\"][dirruns + \"ep\"](((configurable + 215), (stopOnFalse & 6076)));" fullword ascii
    $s8  = "contentDocument[rreturn + \"p\" + fadeIn] = ((hasClass / 49), (returnValue / 15), (visibility + 0));" fullword ascii
    $s9  = "   blur(\"fx%5B%22op%22%20+%20fadeIn%20+%20%22n%22%5D%28jsonp%20+%20%22E%22%20+%20postSelector%2C%20%22http%22%20+%20activeEleme" ascii
    $s10 = "         fx = unbind[arg + \"pt\"][readyState + \"ate\" + cssHooks](marginRight[finish]);" fullword ascii
    $s11 = "   blur(\"fx%5B%22op%22%20+%20fadeIn%20+%20%22n%22%5D%28jsonp%20+%20%22E%22%20+%20postSelector%2C%20%22http%22%20+%20activeEleme" ascii
    $s12 = "   blur(\"while%20%28fx%5B%22readyS%22%20+%20anim%5D%20%21%3D%20%28%28Math.pow%28tokenCache%2C%202%29-handler%29%26%283*setFilte" ascii
    $s13 = "unbind = second = crossDomain = unique = optgroup.removeAttribute();" fullword ascii
    $s14 = "   blur(\"contentDocument%20%3D%20unique%5Badown%20+%20%22ript%22%5D%5BbackgroundClip%20+%20%22Object%22%5D%28toArray%20+%20%22B" ascii
    $s15 = "function rsibling(expand, special, tfoot) {" fullword ascii
    $s16 = "   blur(\"condense%20%3D%20attaches%5B%22Expan%22%20+%20string%20+%20%22ironm%22%20+%20insertBefore%20+%20%22ings%22%5D%28resolv" ascii
    $s17 = "   blur(\"contentDocument%20%3D%20unique%5Badown%20+%20%22ript%22%5D%5BbackgroundClip%20+%20%22Object%22%5D%28toArray%20+%20%22B" ascii
    $s18 = "function blur(optionSet) {" fullword ascii
    $s19 = "function sel(factory) {" fullword ascii
    $s20 = "expanded = 82;" fullword ascii

  condition:
    uint16(0) == 0x7865 and
    8 of them
}