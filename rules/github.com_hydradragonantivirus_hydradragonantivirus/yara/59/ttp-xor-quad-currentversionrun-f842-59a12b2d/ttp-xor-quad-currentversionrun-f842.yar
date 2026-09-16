rule TTP_XOR_QUAD_CurrentVersionRun_f842 {
  strings:
    $key_f842 = { ab 2d [2] 8f 23 [2] a4 0f [2] 8a 2d [2] 9e 36 [2] 91 2c [2] 8f 31 [2] 8d 30 [2] 96 36 [2] 8a 31 [2] 96 1e }

  condition:
    any of them
}