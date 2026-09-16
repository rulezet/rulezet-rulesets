rule TTP_XOR_QUAD_CurrentVersionRun_2608 {
  strings:
    $key_2608 = { 75 67 [2] 51 69 [2] 7a 45 [2] 54 67 [2] 40 7c [2] 4f 66 [2] 51 7b [2] 53 7a [2] 48 7c [2] 54 7b [2] 48 54 }

  condition:
    any of them
}