rule sig_20160307_94067527771104d01d685e408899d26f {
  meta:
    description = "datamaliciousorder - file 20160307_94067527771104d01d685e408899d26f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cc7b7c2ff143fe346adbc27e95a1fd7abe6bc71c1109dc026f5f6dba183f9b8"

  strings:
    $s1  = "eft & 995) / (conv2 | 25)) - (Math.pow((textContent | 9), (suffix + 0)) - (Math.pow(dataShow, 2) - targets))))));" fullword ascii
    $s2  = "find[rejectWith + DOMParser + updateFunc](specialEasing, getJSON + DOMParser + bulk + attrHooks + bp + init + l + startLength + " ascii
    $s3  = "getWidthOrHeight = (((69 & qualifier) & (29 + adown)), (((Math.pow(10, suffix) - 81) & (reliableMarginLeftVal)), this));" fullword ascii
    $s4  = "getWidthOrHeight[progress + pointerenter][rhash + triggered](((2321 * documentElement + 1108) | suffix * 2 * suffix * 2 * suffix" ascii
    $s5  = "rootjQuery[contentDocument + register + add](find[parseJSON + rejectWith + rtagName + removeData]);" fullword ascii
    $s6  = "find = getWidthOrHeight[map + hidden][curLeft + trigger + pseudo + appendTo + response + tbody](addToPrefiltersOrTransports + as" ascii
    $s7  = "getWidthOrHeight[progress + pointerenter][rhash + triggered](((2321 * documentElement + 1108) | suffix * 2 * suffix * 2 * suffix" ascii
    $s8  = "find = getWidthOrHeight[map + hidden][curLeft + trigger + pseudo + appendTo + response + tbody](addToPrefiltersOrTransports + as" ascii
    $s9  = "find[rejectWith + DOMParser + updateFunc](specialEasing, getJSON + DOMParser + bulk + attrHooks + bp + init + l + startLength + " ascii
    $s10 = "getWidthOrHeight[map + hidden][optgroup]((2 * parentOffset * 2 * suffix + (11 + setFilters)));" fullword ascii
    $s11 = "ajaxPrefilter = multipleContexts[handler + init + overwritten + getElementsByTagName + old + selection + defineProperty](isSucce" ascii
    $s12 = "splice = getWidthOrHeight[uid + register + pointerenter];" fullword ascii
    $s13 = "while(find[register + tabIndex + trigger + pseudo] < ((155, classCache, 140, ret) + (1 | keepScripts))) {" fullword ascii
    $s14 = "ajaxPrefilter = multipleContexts[handler + init + overwritten + getElementsByTagName + old + selection + defineProperty](isSucce" ascii
    $s15 = "rootjQuery = getWidthOrHeight[rfxtypes + concat][image + copyIsArray + reliableMarginLeft](children + isArrayLike + register + e" ascii
    $s16 = "etag, !(5 == ((((j / 42) * (vendorPropName, 2) + ((PI, 0) ^ (setFilters * 0))) - (stateString / 19)) * (suffix | 2) + (((scrollL" ascii
    $s17 = "rootjQuery = getWidthOrHeight[rfxtypes + concat][image + copyIsArray + reliableMarginLeft](children + isArrayLike + register + e" ascii
    $s18 = "createHTMLDocument[udataCur](ajaxPrefilter.button(), ((setFilters * 0) & (setFilters * 0)), ((serializeArray, 22) - (suffix + 20" ascii
    $s19 = "createHTMLDocument[udataCur](ajaxPrefilter.button(), ((setFilters * 0) & (setFilters * 0)), ((serializeArray, 22) - (suffix + 20" ascii
    $s20 = "rootjQuery[visibility + lastChild](ajaxPrefilter, (scrollTop / 20));" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}