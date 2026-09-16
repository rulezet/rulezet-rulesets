rule TTP_XOR_QUAD_CurrentVersionRun_381b {
  strings:
    $key_381b = { 6b 74 [2] 4f 7a [2] 64 56 [2] 4a 74 [2] 5e 6f [2] 51 75 [2] 4f 68 [2] 4d 69 [2] 56 6f [2] 4a 68 [2] 56 47 }

  condition:
    any of them
}