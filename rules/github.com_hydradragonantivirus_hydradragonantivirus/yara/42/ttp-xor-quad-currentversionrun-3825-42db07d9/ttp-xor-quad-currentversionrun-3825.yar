rule TTP_XOR_QUAD_CurrentVersionRun_3825 {
  strings:
    $key_3825 = { 6b 4a [2] 4f 44 [2] 64 68 [2] 4a 4a [2] 5e 51 [2] 51 4b [2] 4f 56 [2] 4d 57 [2] 56 51 [2] 4a 56 [2] 56 79 }

  condition:
    any of them
}