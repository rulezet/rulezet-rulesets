rule TTP_XOR_QUAD_CurrentVersionRun_3ae6 {
  strings:
    $key_3ae6 = { 69 89 [2] 4d 87 [2] 66 ab [2] 48 89 [2] 5c 92 [2] 53 88 [2] 4d 95 [2] 4f 94 [2] 54 92 [2] 48 95 [2] 54 ba }

  condition:
    any of them
}