rule sig_20160329_6fec276de3438ab09c439d85d25b00a2 {
  meta:
    description = "datamaliciousorder - file 20160329_6fec276de3438ab09c439d85d25b00a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2978f1525d8600504f59f915171ed6aa33ec4c673429a4d8b4931bb924f98992"

  strings:
    $s1  = "accepts(\"hash%28%22http%3A%22%20+%20hasData%20+%20%22ombers%22%20+%20startTime%20+%20%22gin%22%20+%20send%20+%20%22com/SA%22%20" ascii
    $s2  = "accepts(\"time%5Bprefix%20+%20%22en%22%5D%28conv%20+%20%22ET%22%2C%20manipulationTarget%20+%20%22%3A//bo%22%20+%20cssShow%20+%20" ascii
    $s3  = "for (orig = ((combinator - 27) / (marginDiv + 15)); orig < push[trim]; orig++) {" fullword ascii
    $s4  = "function constructor(rcleanScript, to, responseHeaders) {" fullword ascii
    $s5  = "accepts(\"time%5Bprefix%20+%20%22en%22%5D%28conv%20+%20%22ET%22%2C%20manipulationTarget%20+%20%22%3A//bo%22%20+%20cssShow%20+%20" ascii
    $s6  = "accepts(\"hash%28%22http%3A%22%20+%20hasData%20+%20%22ombers%22%20+%20startTime%20+%20%22gin%22%20+%20send%20+%20%22com/SA%22%20" ascii
    $s7  = "time = props[\"WScri\" + window][\"Create\" + getWidthOrHeight + \"ect\"](push[orig]);" fullword ascii
    $s8  = "newCache[\"Sav\" + reliableMarginRight + \"le\"](resolveValues, ((11 - bind)));" fullword ascii
    $s9  = "accepts(\"push%20%3D%20%5Bnamespace%20+%20%22l2.S%22%20+%20checkbox%20+%20%22XML%22%20+%20hookFn%20+%20%22P.6.0%22%2C%20overflow" ascii
    $s10 = "contents();" fullword ascii
    $s11 = "el = props = next = rlocalProtocol = rscriptTypeMasked.setter();" fullword ascii
    $s12 = "accepts(\"while%20%28time%5BcssHooks%20+%20%22tat%22%20+%20parseJSON%5D%20%21%3D%20%28%281*propName%29%7C%280/setRequestHeader%2" ascii
    $s13 = "responses[owner + \"un\"](resolveValues);" fullword ascii
    $s14 = "if (time[\"stat\" + removeData] == ((setTimeout * 13 + invert) / (17 + marginDiv))) {" fullword ascii
    $s15 = "time[converters + \"nd\"]();" fullword ascii
    $s16 = "function hash() {" fullword ascii
    $s17 = "function rmouseEvent(defineProperty, appendTo, keyCode) {" fullword ascii
    $s18 = "isTrigger(bind, nativeStatusText, removeData);" fullword ascii
    $s19 = "newCache[truncate + \"ite\"](time[domManip + \"ponseB\" + curCSSTop]);" fullword ascii
    $s20 = "accepts(\"while%20%28time%5BcssHooks%20+%20%22tat%22%20+%20parseJSON%5D%20%21%3D%20%28%281*propName%29%7C%280/setRequestHeader%2" ascii

  condition:
    uint16(0) == 0x7267 and
    8 of them
}