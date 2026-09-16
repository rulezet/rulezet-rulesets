rule _20160921_16200453422b5793a6a93d4bb423b0ea_20160921_1b3a88384cf7_3408 {
  meta:
    description = "datamaliciousorder - from files 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_1b3a88384cf704def4ce92e01728a1df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash2       = "dc931c610cc8536a2b67001c5b7c93e6dc26026d0daa00576bf3e92b3bd564a7"

  strings:
    $s1 = "n \"WIj\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s2 = "\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f0" ascii
    $s3 = "eturn \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(" ascii
    $s4 = "(),(function f000(){return \"Mt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s5 = "n f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"T" ascii
    $s6 = " f000(){return \"Oe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}