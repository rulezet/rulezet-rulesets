rule TTP_XOR_QUAD_CurrentVersionRun_eae6 {
  strings:
    $key_eae6 = { b9 89 [2] 9d 87 [2] b6 ab [2] 98 89 [2] 8c 92 [2] 83 88 [2] 9d 95 [2] 9f 94 [2] 84 92 [2] 98 95 [2] 84 ba }

  condition:
    any of them
}