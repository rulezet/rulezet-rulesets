rule sig_20160329_808776f074068e4baa78da523b2ab0a3 {
  meta:
    description = "datamaliciousorder - file 20160329_808776f074068e4baa78da523b2ab0a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c234b8dcc328d784156c1242308c3db73bcc8dbe464a3c715849fcc187fbd310"

  strings:
    $s1  = "getById[evt + \"pt\"][copyIsArray](((method - 2373) | (nType * 9 + winnow)));" fullword ascii
    $s2  = "dataUser(\"traditional%5BattrId%20+%20%22en%22%5D%28jsonp%20+%20%22T%22%2C%20cssFn%20+%20%22//a%22%20+%20eventDoc%20+%20%22kac%2" ascii
    $s3  = "dataUser(\"height%20%3D%20%5B%22Msxm%22%20+%20win%20+%20%22erve%22%20+%20pageX%20+%20%22TP.6.%22%20+%20nodeNameSelector%2C%20%22" ascii
    $s4  = "forward(getBoundingClientRect, clearCloneStyle, clearInterval);" fullword ascii
    $s5  = "if(traditional[firstElementChild + \"tat\" + parseJSON] == (233 & (configurable / 47))) {" fullword ascii
    $s6  = "dataUser(\"while%20%28traditional%5B%22readyS%22%20+%20clearInterval%20+%20%22e%22%5D%20%21%3D%20%28%28prefix+0%29*%28rcheckable" ascii
    $s7  = "function forward() {" fullword ascii
    $s8  = "pageYOffset[\"SaveT\" + inspect + \"le\"](divStyle, ((3 & prefix) & (3 + createDocumentFragment)));" fullword ascii
    $s9  = "pageYOffset[\"Wri\" + unit](traditional[\"resp\" + noCloneChecked + \"dy\"]);" fullword ascii
    $s10 = "pageYOffset[input + \"od\" + parents] = ((1 * setup) | (0 | createDocumentFragment));" fullword ascii
    $s11 = "function activeElement(truncate, width, host) {" fullword ascii
    $s12 = "for(parentsUntil = (0 | createDocumentFragment); parentsUntil < height[charset + \"ng\" + updateFunc]; parentsUntil++) {" fullword ascii
    $s13 = "traditional[firstElementChild + \"en\" + results]();" fullword ascii
    $s14 = "traditional = timeout[\"WScr\" + prototype][\"Crea\" + each + \"ect\"](height[parentsUntil]);" fullword ascii
    $s15 = "dataUser(\"traditional%5BattrId%20+%20%22en%22%5D%28jsonp%20+%20%22T%22%2C%20cssFn%20+%20%22//a%22%20+%20eventDoc%20+%20%22kac%2" ascii
    $s16 = "function inspectPrefiltersOrTransports(toArray, clientTop) {" fullword ascii
    $s17 = "inspectPrefiltersOrTransports(top, each, clearInterval);" fullword ascii
    $s18 = "function dataUser(rmsPrefix) {" fullword ascii
    $s19 = "dataUser(\"height%20%3D%20%5B%22Msxm%22%20+%20win%20+%20%22erve%22%20+%20pageX%20+%20%22TP.6.%22%20+%20nodeNameSelector%2C%20%22" ascii
    $s20 = "dataUser(\"while%20%28traditional%5B%22readyS%22%20+%20clearInterval%20+%20%22e%22%5D%20%21%3D%20%28%28prefix+0%29*%28rcheckable" ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}