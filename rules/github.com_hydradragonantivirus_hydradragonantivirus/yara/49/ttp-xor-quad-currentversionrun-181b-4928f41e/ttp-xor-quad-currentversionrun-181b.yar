rule TTP_XOR_QUAD_CurrentVersionRun_181b {
  strings:
    $key_181b = { 4b 74 [2] 6f 7a [2] 44 56 [2] 6a 74 [2] 7e 6f [2] 71 75 [2] 6f 68 [2] 6d 69 [2] 76 6f [2] 6a 68 [2] 76 47 }

  condition:
    any of them
}