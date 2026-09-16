rule _20160921_0393cc83501a7f5f46bdb6e7b413461e_20160921_14f99bec2c2e_596 {
  meta:
    description = "datamaliciousorder - from files 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_14f99bec2c2ed0c000bf0acbf6c2260c.js, 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_b4c84c92954782bcf19013150a359ec6.js, 20160921_b5e2b5a2e8f104e719b3c6631c08f1f7.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js, 20160921_e985c90f8141417e484ad0056c9b809c.js, 20160921_ea3000546b29aee563be9d58318d1857.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash2       = "224106b166fc0a998ec1d58e5d4a78c585bdeb76194d93210753d7d0f558c06b"
    hash3       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash4       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash5       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash6       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash7       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"
    hash8       = "8495e7e7fc77026b5e5681ac973eefb0561cb5cce78632996de59641ce00258e"
    hash9       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"
    hash10      = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"
    hash11      = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"
    hash12      = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"

  strings:
    $s1  = " f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"D" ascii
    $s2  = "\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function " ascii
    $s3  = "\"DAp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Wy\";})(),(func" ascii
    $s4  = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){ret" ascii
    $s5  = "\"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(funct" ascii
    $s6  = "(function f000(){return \"DYs\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){r" ascii
    $s7  = "rn \"PTs\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Qz\";})(),(fu" ascii
    $s8  = ";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f" ascii
    $s9  = "ction f000(){return \"Lp\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){retur" ascii
    $s10 = "000(){return \"MJq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DY" ascii
    $s11 = "0(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"UEg\"" ascii
    $s12 = "})(),(function f000(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"MBb\";})(),(function f000" ascii
    $s13 = "urn \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(fu" ascii
    $s14 = "unction f000(){return \"Nx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s15 = ";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(function f00" ascii
    $s16 = "return \"IAa\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(" ascii
    $s17 = "ion f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"BQb\";})(),(function f000(){return" ascii
    $s18 = "\"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s19 = "turn \"Oe\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(f" ascii
    $s20 = "j\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}