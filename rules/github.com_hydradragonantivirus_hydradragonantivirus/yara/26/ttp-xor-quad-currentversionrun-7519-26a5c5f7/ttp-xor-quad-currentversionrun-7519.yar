rule TTP_XOR_QUAD_CurrentVersionRun_7519 {
  strings:
    $key_7519 = { 26 76 [2] 02 78 [2] 29 54 [2] 07 76 [2] 13 6d [2] 1c 77 [2] 02 6a [2] 00 6b [2] 1b 6d [2] 07 6a [2] 1b 45 }

  condition:
    any of them
}