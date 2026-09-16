rule TTP_XOR_QUAD_CurrentVersionRun_f857 {
  strings:
    $key_f857 = { ab 38 [2] 8f 36 [2] a4 1a [2] 8a 38 [2] 9e 23 [2] 91 39 [2] 8f 24 [2] 8d 25 [2] 96 23 [2] 8a 24 [2] 96 0b }

  condition:
    any of them
}