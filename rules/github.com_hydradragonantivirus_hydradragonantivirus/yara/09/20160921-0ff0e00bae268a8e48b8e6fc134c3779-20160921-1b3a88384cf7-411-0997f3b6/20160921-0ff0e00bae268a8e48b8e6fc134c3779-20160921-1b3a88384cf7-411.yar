rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_1b3a88384cf7_411 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_1b3a88384cf704def4ce92e01728a1df.js, 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_570295874daef65ccf11d909395ae377.js, 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js, 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js, 20160921_b132808f30a4f3b5c484e9734dc93fcc.js, 20160921_b71168af39c5eec1d403d381eea7ffe1.js, 20160921_e1c974d7750547ace34afdda5a06de15.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "dc931c610cc8536a2b67001c5b7c93e6dc26026d0daa00576bf3e92b3bd564a7"
    hash3       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash4       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash5       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"
    hash6       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash7       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"
    hash8       = "03f070dd06dae48f7c253ddc9a238e441aaac22f9de6e238ba5d3ffa0b9220b4"
    hash9       = "c8811edeb74999e8dd226f7fa9d7963ccfc998904ecb9474d036376253dc6fde"
    hash10      = "bed4e8c71e09f1ca8c800564bc43d4e103353ec558d1f0869c85d3e8f8c43b01"
    hash11      = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1  = "n f000(){return \"Vj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GG" ascii
    $s2  = "Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s3  = "ion f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s4  = "nction f000(){return \"Qa\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BMj\";})(),(function f000(){retu" ascii
    $s5  = "{return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Nx\";})()" ascii
    $s6  = "urn \"PTi\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(f" ascii
    $s7  = "eturn \"PTi\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s8  = "00(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"UEg\"" ascii
    $s9  = "n \"Vu\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s10 = "n f000(){return \"Br\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br" ascii
    $s11 = "})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(function f000" ascii
    $s12 = "{return \"Br\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(" ascii
    $s13 = ";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYs\";})(),(function f0" ascii
    $s14 = "\"Tb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s15 = "n f000(){return \"RVb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s16 = "tion f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){retur" ascii
    $s17 = "f000(){return \"Nx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s18 = " f000(){return \"YTp\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"" ascii
    $s19 = "unction f000(){return \"DAp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Nx\";})(),(function f000(){retu" ascii
    $s20 = "on f000(){return \"Vu\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}