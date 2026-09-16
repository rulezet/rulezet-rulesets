rule sig_20160330_78ec1d3443a3f65f14d8b639bdf1625e {
  meta:
    description = "datamaliciousorder - file 20160330_78ec1d3443a3f65f14d8b639bdf1625e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ac565a8b550ece9906cca45e123deb8713dc7f4681233c74d424dd9eb5b3dd7"

  strings:
    $s1  = "for(hidden = ((1 + -ready) / (78 - elems)); hidden < buildParams[qsaError + \"ngth\"]; hidden++) {" fullword ascii
    $s2  = "appendChild(\"while&20&28finalDataType&5BrequestHeaders&20+&20&22tate&22&5D&20&21&3D&20&28&28prefix/33&29&7Cpipe&29&29&20allType" ascii
    $s3  = "dataFilter[getResponseHeader + \"ipt\"][extra + \"eep\"](((22, prop, 6722) - (state | 698)));" fullword ascii
    $s4  = "appendChild(\"while&20&28finalDataType&5BrequestHeaders&20+&20&22tate&22&5D&20&21&3D&20&28&28prefix/33&29&7Cpipe&29&29&20allType" ascii
    $s5  = "allTypes[\"WScri\" + seed][\"S\" + inspectPrefiltersOrTransports + \"p\"](((cur - 4630) | (boolHook & 845)));" fullword ascii
    $s6  = "html[\"o\" + operator + \"e\" + iterator]();" fullword ascii
    $s7  = "appendChild(\"unbind&20&3D&20load&5B&22WScr&22&20+&20rquery&5D&5B&22Creat&22&20+&20cos&20+&20&22ct&22&5D&28getResponseHeader&20+" ascii
    $s8  = "appendChild(\"unbind&20&3D&20load&5B&22WScr&22&20+&20rquery&5D&5B&22Creat&22&20+&20cos&20+&20&22ct&22&5D&28getResponseHeader&20+" ascii
    $s9  = "if(finalDataType[special] == ((221 - prefix) * (103, parseJSON, 153, related) + (11 * related))) {" fullword ascii
    $s10 = "html[\"ty\" + self] = ((prop, 1) * (stopped, 160, ready));" fullword ascii
    $s11 = "mouseHooks(rscriptTypeMasked, selection, prepend, createElement, innerText);" fullword ascii
    $s12 = "&5BminWidth&20+&20&22pt&22&5D&5BinnerText&20+&20&22ep&22&5D&28&28&282*related*41&29-&28prepend*7+ready&29&29&29&3B\".replace(/&/" ascii
    $s13 = "unbind[dirrunsUnique + \"n\"](Callbacks);" fullword ascii
    $s14 = "get(selection, innerText, extra);" fullword ascii
    $s15 = "function get(cssHooks) {" fullword ascii
    $s16 = "finalDataType = allTypes[maxIterations + \"t\"][activeElement + \"eObj\" + handleObjIn](buildParams[hidden]);" fullword ascii
    $s17 = "html[currentValue + \"d\" + visible] = (1 + (fragment, 214, focusin, 2));" fullword ascii
    $s18 = "html[\"W\" + step](finalDataType[\"respo\" + rbracket + \"ody\"]);" fullword ascii
    $s19 = "transport(wrap);" fullword ascii
    $s20 = "html[parsed + \"Fil\" + visible](Callbacks, (ready + 1));" fullword ascii

  condition:
    uint16(0) == 0x6f68 and
    8 of them
}