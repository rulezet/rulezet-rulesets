rule TTP_XOR_QUAD_CurrentVersionRun_ce24 {
  strings:
    $key_ce24 = { 9d 4b [2] b9 45 [2] 92 69 [2] bc 4b [2] a8 50 [2] a7 4a [2] b9 57 [2] bb 56 [2] a0 50 [2] bc 57 [2] a0 78 }

  condition:
    any of them
}