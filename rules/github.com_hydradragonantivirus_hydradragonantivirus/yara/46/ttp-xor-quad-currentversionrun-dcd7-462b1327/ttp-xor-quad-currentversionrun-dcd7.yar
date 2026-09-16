rule TTP_XOR_QUAD_CurrentVersionRun_dcd7 {
  strings:
    $key_dcd7 = { 8f b8 [2] ab b6 [2] 80 9a [2] ae b8 [2] ba a3 [2] b5 b9 [2] ab a4 [2] a9 a5 [2] b2 a3 [2] ae a4 [2] b2 8b }

  condition:
    any of them
}