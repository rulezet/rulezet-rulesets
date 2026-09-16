rule TTP_XOR_QUAD_CurrentVersionRun_3af7 {
  strings:
    $key_3af7 = { 69 98 [2] 4d 96 [2] 66 ba [2] 48 98 [2] 5c 83 [2] 53 99 [2] 4d 84 [2] 4f 85 [2] 54 83 [2] 48 84 [2] 54 ab }

  condition:
    any of them
}