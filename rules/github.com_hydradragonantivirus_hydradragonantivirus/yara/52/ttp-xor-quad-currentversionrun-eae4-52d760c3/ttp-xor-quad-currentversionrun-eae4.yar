rule TTP_XOR_QUAD_CurrentVersionRun_eae4 {
  strings:
    $key_eae4 = { b9 8b [2] 9d 85 [2] b6 a9 [2] 98 8b [2] 8c 90 [2] 83 8a [2] 9d 97 [2] 9f 96 [2] 84 90 [2] 98 97 [2] 84 b8 }

  condition:
    any of them
}