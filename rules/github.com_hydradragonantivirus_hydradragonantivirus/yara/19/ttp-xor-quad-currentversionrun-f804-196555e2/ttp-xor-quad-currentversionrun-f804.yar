rule TTP_XOR_QUAD_CurrentVersionRun_f804 {
  strings:
    $key_f804 = { ab 6b [2] 8f 65 [2] a4 49 [2] 8a 6b [2] 9e 70 [2] 91 6a [2] 8f 77 [2] 8d 76 [2] 96 70 [2] 8a 77 [2] 96 58 }

  condition:
    any of them
}