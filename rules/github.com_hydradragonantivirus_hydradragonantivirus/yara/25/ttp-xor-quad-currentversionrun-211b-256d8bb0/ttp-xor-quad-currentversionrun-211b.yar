rule TTP_XOR_QUAD_CurrentVersionRun_211b {
  strings:
    $key_211b = { 72 74 [2] 56 7a [2] 7d 56 [2] 53 74 [2] 47 6f [2] 48 75 [2] 56 68 [2] 54 69 [2] 4f 6f [2] 53 68 [2] 4f 47 }

  condition:
    any of them
}