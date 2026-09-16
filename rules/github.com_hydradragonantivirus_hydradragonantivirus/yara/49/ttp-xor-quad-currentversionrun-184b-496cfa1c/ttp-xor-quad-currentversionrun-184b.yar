rule TTP_XOR_QUAD_CurrentVersionRun_184b {
  strings:
    $key_184b = { 4b 24 [2] 6f 2a [2] 44 06 [2] 6a 24 [2] 7e 3f [2] 71 25 [2] 6f 38 [2] 6d 39 [2] 76 3f [2] 6a 38 [2] 76 17 }

  condition:
    any of them
}