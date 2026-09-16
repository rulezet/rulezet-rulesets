rule TTP_XOR_QUAD_CurrentVersionRun_3f37 {
  strings:
    $key_3f37 = { 6c 58 [2] 48 56 [2] 63 7a [2] 4d 58 [2] 59 43 [2] 56 59 [2] 48 44 [2] 4a 45 [2] 51 43 [2] 4d 44 [2] 51 6b }

  condition:
    any of them
}