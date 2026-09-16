rule sig_20160307_d0a754874fae864a8cf3c756b692ee53 {
  meta:
    description = "datamaliciousorder - file 20160307_d0a754874fae864a8cf3c756b692ee53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed8f9b00c11f6a4f50214cbdcea1f7c94d7fc65475ac6684f2ca0bdb3e29a3ef"

  strings:
    $s1  = "selected[bool + name](global, rquery + arr + newDefer + rfocusMorph + classes + rtrim + timeStamp + what + rjsonp + clientTop + " ascii
    $s2  = "off = target[finish + fast + _removeData + firstElementChild + marginRight + parentOffset + headers + pop](curLeft + arr) + firs" ascii
    $s3  = "target = cssHooks[ajaxPrefilter + visible + statusText + teardown](parseOnly + types + cloneNode + rpseudo + subtract);" fullword ascii
    $s4  = "t)) - ((65 + stopImmediatePropagation) / 11 * bulk * 2))) - (((clone & 37) - (load / 50)) * ((rcleanScript + 3) + (optSelected -" ascii
    $s5  = "unbind = (((263 ^ disable) - (Math.pow(22, bulk) - 442)), (((once, 97, progressValues) / 5 * old * 3), this));" fullword ascii
    $s6  = "off = target[finish + fast + _removeData + firstElementChild + marginRight + parentOffset + headers + pop](curLeft + arr) + firs" ascii
    $s7  = "isSuccess[anim](off.noGlobal(), ((102 + beforeunload), (189 & interval), (0 ^ compiled)), (0 ^ (rcleanScript * 0)));" fullword ascii
    $s8  = "selected = unbind[close + rparentsprev][ajaxPrefilter + visible + iNoClone + uid](getById + handlerQueue + elem);" fullword ascii
    $s9  = "while(selected[cssFn + rnoContent] < ((1624 / compile) / (2 + optSelected))) {" fullword ascii
    $s10 = "curLeft = \"%TEMP%\";" fullword ascii
    $s11 = "stop, !((Math.pow((((returnFalse / 30) + (compiled ^ 1)) + bulk * (20 / end)), (((30 * bulk + 14), (startTime * 3 + disableScrip" ascii
    $s12 = "isSuccess = target;" fullword ascii
    $s13 = "lock = \"WScr\", file = \"eBody\", cssFn = \"read\", getById = \"MSXML2\", rparentsprev = \"cript\";" fullword ascii
    $s14 = "cssHooks = unbind[close + tweeners + ajaxConvert];" fullword ascii
    $s15 = "unbind[lock + cloneNode][clientLeft](((205, serialize) + (105 | gotoEnd)));" fullword ascii
    $s16 = "parents[selector] = (1 + (compiled | 0));" fullword ascii
    $s17 = "unbind[lock + cloneNode][stateVal + notify](((67 ^ properties) & (140, noCloneChecked)));" fullword ascii
    $s18 = "method = \".scr\"," fullword ascii
    $s19 = "rcleanScript = 1, properties = (function Object.prototype.noGlobal() {" fullword ascii
    $s20 = "defer = \"close\", cloneNode = \"ipt\", disable = 65, global = \"GET\", timeStamp = \"i.\", resolveValues = \"Cre\";" fullword ascii

  condition:
    uint16(0) == 0x7472 and
    8 of them
}