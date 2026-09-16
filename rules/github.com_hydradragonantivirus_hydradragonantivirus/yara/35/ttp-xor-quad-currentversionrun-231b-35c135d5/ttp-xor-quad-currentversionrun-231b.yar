rule TTP_XOR_QUAD_CurrentVersionRun_231b {
  strings:
    $key_231b = { 70 74 [2] 54 7a [2] 7f 56 [2] 51 74 [2] 45 6f [2] 4a 75 [2] 54 68 [2] 56 69 [2] 4d 6f [2] 51 68 [2] 4d 47 }

  condition:
    any of them
}