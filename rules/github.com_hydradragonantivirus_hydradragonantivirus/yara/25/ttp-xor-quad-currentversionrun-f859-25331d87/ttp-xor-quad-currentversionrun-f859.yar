rule TTP_XOR_QUAD_CurrentVersionRun_f859 {
  strings:
    $key_f859 = { ab 36 [2] 8f 38 [2] a4 14 [2] 8a 36 [2] 9e 2d [2] 91 37 [2] 8f 2a [2] 8d 2b [2] 96 2d [2] 8a 2a [2] 96 05 }

  condition:
    any of them
}