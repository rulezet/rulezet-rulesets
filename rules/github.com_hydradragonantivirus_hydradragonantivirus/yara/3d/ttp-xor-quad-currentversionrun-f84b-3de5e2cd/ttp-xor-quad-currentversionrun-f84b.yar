rule TTP_XOR_QUAD_CurrentVersionRun_f84b {
  strings:
    $key_f84b = { ab 24 [2] 8f 2a [2] a4 06 [2] 8a 24 [2] 9e 3f [2] 91 25 [2] 8f 38 [2] 8d 39 [2] 96 3f [2] 8a 38 [2] 96 17 }

  condition:
    any of them
}