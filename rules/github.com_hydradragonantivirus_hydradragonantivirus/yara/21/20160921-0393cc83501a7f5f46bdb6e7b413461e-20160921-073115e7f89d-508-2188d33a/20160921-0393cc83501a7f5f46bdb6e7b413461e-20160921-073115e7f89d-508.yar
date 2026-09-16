rule _20160921_0393cc83501a7f5f46bdb6e7b413461e_20160921_073115e7f89d_508 {
  meta:
    description = "datamaliciousorder - from files 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_14f99bec2c2ed0c000bf0acbf6c2260c.js, 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_50ddf5c101f65dbae1a99b5967b69eaf.js, 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_6b34f0b83cb5d89ac574db511a389f02.js, 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js, 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_b4c84c92954782bcf19013150a359ec6.js, 20160921_b5e2b5a2e8f104e719b3c6631c08f1f7.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js, 20160921_e985c90f8141417e484ad0056c9b809c.js, 20160921_ea3000546b29aee563be9d58318d1857.js, 20160921_ec2541ade561a4750092fda52be6f269.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash2       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash3       = "224106b166fc0a998ec1d58e5d4a78c585bdeb76194d93210753d7d0f558c06b"
    hash4       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash5       = "4d3df92f56e6b5cba10c96e8cd182f92f3c10aceaabe5a4530b70d3fc5873feb"
    hash6       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash7       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash8       = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"
    hash9       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"
    hash10      = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash11      = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash12      = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash13      = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash14      = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"
    hash15      = "8495e7e7fc77026b5e5681ac973eefb0561cb5cce78632996de59641ce00258e"
    hash16      = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"
    hash17      = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"
    hash18      = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"
    hash19      = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"
    hash20      = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"
    hash21      = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"
    hash22      = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"
    hash23      = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"
    hash24      = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1  = "n f000(){return \"Yz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s2  = "){return \"Go\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(" ascii
    $s3  = "0(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"RPt\"" ascii
    $s4  = "f000(){return \"MBb\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"K" ascii
    $s5  = "000(){return \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\"" ascii
    $s6  = "function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){ret" ascii
    $s7  = "0(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Uo\";})" ascii
    $s8  = "rn \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(fun" ascii
    $s9  = "unction f000(){return \"Vu\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){retur" ascii
    $s10 = "ction f000(){return \"PTi\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"NYh\";})(),(function f000(){retur" ascii
    $s11 = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Nx\";})(),(f" ascii
    $s12 = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"PTs\";})(),(fun" ascii
    $s13 = "rn \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(fu" ascii
    $s14 = "0(){return \"Br\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Br\";}" ascii
    $s15 = ";})(),(function f000(){return \"Br\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f00" ascii
    $s16 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZIi\";})(),(function f" ascii
    $s17 = " f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GG" ascii
    $s18 = "Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br\";})(),(function" ascii
    $s19 = "){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})" ascii
    $s20 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Vu\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}