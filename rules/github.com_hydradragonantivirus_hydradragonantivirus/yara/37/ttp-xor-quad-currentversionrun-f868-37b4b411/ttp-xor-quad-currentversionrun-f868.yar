rule TTP_XOR_QUAD_CurrentVersionRun_f868 {
  strings:
    $key_f868 = { ab 07 [2] 8f 09 [2] a4 25 [2] 8a 07 [2] 9e 1c [2] 91 06 [2] 8f 1b [2] 8d 1a [2] 96 1c [2] 8a 1b [2] 96 34 }

  condition:
    any of them
}