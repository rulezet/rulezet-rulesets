rule TTP_XOR_QUAD_CurrentVersionRun_f82b {
  strings:
    $key_f82b = { ab 44 [2] 8f 4a [2] a4 66 [2] 8a 44 [2] 9e 5f [2] 91 45 [2] 8f 58 [2] 8d 59 [2] 96 5f [2] 8a 58 [2] 96 77 }

  condition:
    any of them
}