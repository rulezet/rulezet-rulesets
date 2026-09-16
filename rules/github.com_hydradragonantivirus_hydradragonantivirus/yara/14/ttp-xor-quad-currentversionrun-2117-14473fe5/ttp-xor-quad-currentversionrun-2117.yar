rule TTP_XOR_QUAD_CurrentVersionRun_2117 {
  strings:
    $key_2117 = { 72 78 [2] 56 76 [2] 7d 5a [2] 53 78 [2] 47 63 [2] 48 79 [2] 56 64 [2] 54 65 [2] 4f 63 [2] 53 64 [2] 4f 4b }

  condition:
    any of them
}