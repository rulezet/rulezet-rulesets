rule TTP_XOR_QUAD_CurrentVersionRun_0f1b {
  strings:
    $key_0f1b = { 5c 74 [2] 78 7a [2] 53 56 [2] 7d 74 [2] 69 6f [2] 66 75 [2] 78 68 [2] 7a 69 [2] 61 6f [2] 7d 68 [2] 61 47 }

  condition:
    any of them
}