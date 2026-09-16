rule TTP_XOR_QUAD_CurrentVersionRun_eaf7 {
  strings:
    $key_eaf7 = { b9 98 [2] 9d 96 [2] b6 ba [2] 98 98 [2] 8c 83 [2] 83 99 [2] 9d 84 [2] 9f 85 [2] 84 83 [2] 98 84 [2] 84 ab }

  condition:
    any of them
}