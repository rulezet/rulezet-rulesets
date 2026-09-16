rule _20160921_0393cc83501a7f5f46bdb6e7b413461e_20160921_649e29a058d1_4172 {
  meta:
    description = "datamaliciousorder - from files 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_b132808f30a4f3b5c484e9734dc93fcc.js, 20160921_e1c974d7750547ace34afdda5a06de15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash2       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash3       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash4       = "03f070dd06dae48f7c253ddc9a238e441aaac22f9de6e238ba5d3ffa0b9220b4"
    hash5       = "bed4e8c71e09f1ca8c800564bc43d4e103353ec558d1f0869c85d3e8f8c43b01"

  strings:
    $s1 = "\"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s2 = "f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn" ascii
    $s3 = "unction f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){ret" ascii
    $s4 = "rn \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s5 = "ion f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}