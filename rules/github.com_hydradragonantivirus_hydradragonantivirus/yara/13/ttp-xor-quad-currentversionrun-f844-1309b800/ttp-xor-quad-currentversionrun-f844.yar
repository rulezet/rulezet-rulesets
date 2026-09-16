rule TTP_XOR_QUAD_CurrentVersionRun_f844 {
  strings:
    $key_f844 = { ab 2b [2] 8f 25 [2] a4 09 [2] 8a 2b [2] 9e 30 [2] 91 2a [2] 8f 37 [2] 8d 36 [2] 96 30 [2] 8a 37 [2] 96 18 }

  condition:
    any of them
}