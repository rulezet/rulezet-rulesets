rule TTP_XOR_QUAD_CurrentVersionRun_f80b {
  strings:
    $key_f80b = { ab 64 [2] 8f 6a [2] a4 46 [2] 8a 64 [2] 9e 7f [2] 91 65 [2] 8f 78 [2] 8d 79 [2] 96 7f [2] 8a 78 [2] 96 57 }

  condition:
    any of them
}