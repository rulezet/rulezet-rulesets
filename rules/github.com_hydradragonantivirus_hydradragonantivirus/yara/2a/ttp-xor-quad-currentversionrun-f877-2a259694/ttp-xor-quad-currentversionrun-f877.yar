rule TTP_XOR_QUAD_CurrentVersionRun_f877 {
  strings:
    $key_f877 = { ab 18 [2] 8f 16 [2] a4 3a [2] 8a 18 [2] 9e 03 [2] 91 19 [2] 8f 04 [2] 8d 05 [2] 96 03 [2] 8a 04 [2] 96 2b }

  condition:
    any of them
}