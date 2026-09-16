rule TTP_XOR_QUAD_CurrentVersionRun_085b {
  strings:
    $key_085b = { 5b 34 [2] 7f 3a [2] 54 16 [2] 7a 34 [2] 6e 2f [2] 61 35 [2] 7f 28 [2] 7d 29 [2] 66 2f [2] 7a 28 [2] 66 07 }

  condition:
    any of them
}