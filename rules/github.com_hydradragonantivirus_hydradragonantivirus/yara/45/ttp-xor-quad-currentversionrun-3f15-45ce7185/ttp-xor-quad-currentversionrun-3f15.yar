rule TTP_XOR_QUAD_CurrentVersionRun_3f15 {
  strings:
    $key_3f15 = { 6c 7a [2] 48 74 [2] 63 58 [2] 4d 7a [2] 59 61 [2] 56 7b [2] 48 66 [2] 4a 67 [2] 51 61 [2] 4d 66 [2] 51 49 }

  condition:
    any of them
}