rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_267_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_267_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c55dc9d371126fb891d66dcf529ce68062ebbac7cc0ebb9c666e3029e36578b"

  strings:
    $s1 = "Heco pememejajajizox xajokugeyalup xekos cigogunofedimu. Peludayehehiw zepivicitekob xowoge gusagofewid. Leyifobamoj wupaxaroca " ascii
    $s2 = "ce muwatop rixurapihoc. Xikab. Mode yodacitiyumuxe. Tev ropucopodivunu yuhezufop pap. Teviduxo pahosefoy ficiximaput ruxicipebe." ascii
    $s3 = "Mis tonic tazitodesaluso tohumawew zovoginipak" fullword ascii
    $s4 = "YPuzodobopi zisotumuboxo bipabunofixo tegalewikic pihalapaxeku sahasuwolok tate puwokigufe:Zovuv lizezedesebanew dukomehesex sif" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}