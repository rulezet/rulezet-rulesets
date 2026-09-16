rule TTP_XOR_QUAD_CurrentVersionRun_dcd6 {
  strings:
    $key_dcd6 = { 8f b9 [2] ab b7 [2] 80 9b [2] ae b9 [2] ba a2 [2] b5 b8 [2] ab a5 [2] a9 a4 [2] b2 a2 [2] ae a5 [2] b2 8a }

  condition:
    any of them
}