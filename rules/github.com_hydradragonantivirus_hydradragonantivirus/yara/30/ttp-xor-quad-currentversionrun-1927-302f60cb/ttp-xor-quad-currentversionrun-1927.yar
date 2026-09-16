rule TTP_XOR_QUAD_CurrentVersionRun_1927 {
  strings:
    $key_1927 = { 4a 48 [2] 6e 46 [2] 45 6a [2] 6b 48 [2] 7f 53 [2] 70 49 [2] 6e 54 [2] 6c 55 [2] 77 53 [2] 6b 54 [2] 77 7b }

  condition:
    any of them
}