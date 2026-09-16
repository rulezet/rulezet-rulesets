rule TTP_XOR_QUAD_CurrentVersionRun_0724 {
  strings:
    $key_0724 = { 54 4b [2] 70 45 [2] 5b 69 [2] 75 4b [2] 61 50 [2] 6e 4a [2] 70 57 [2] 72 56 [2] 69 50 [2] 75 57 [2] 69 78 }

  condition:
    any of them
}