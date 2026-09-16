rule TTP_XOR_QUAD_CurrentVersionRun_2124 {
  strings:
    $key_2124 = { 72 4b [2] 56 45 [2] 7d 69 [2] 53 4b [2] 47 50 [2] 48 4a [2] 56 57 [2] 54 56 [2] 4f 50 [2] 53 57 [2] 4f 78 }

  condition:
    any of them
}