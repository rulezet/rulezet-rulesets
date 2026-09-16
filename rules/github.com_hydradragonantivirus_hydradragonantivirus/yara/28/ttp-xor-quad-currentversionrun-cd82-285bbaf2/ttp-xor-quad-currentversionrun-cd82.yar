rule TTP_XOR_QUAD_CurrentVersionRun_cd82 {
  strings:
    $key_cd82 = { 9e ed [2] ba e3 [2] 91 cf [2] bf ed [2] ab f6 [2] a4 ec [2] ba f1 [2] b8 f0 [2] a3 f6 [2] bf f1 [2] a3 de }

  condition:
    any of them
}