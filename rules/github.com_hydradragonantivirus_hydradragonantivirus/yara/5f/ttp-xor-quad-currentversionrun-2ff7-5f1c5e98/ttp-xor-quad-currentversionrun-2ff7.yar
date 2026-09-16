rule TTP_XOR_QUAD_CurrentVersionRun_2ff7 {
  strings:
    $key_2ff7 = { 7c 98 [2] 58 96 [2] 73 ba [2] 5d 98 [2] 49 83 [2] 46 99 [2] 58 84 [2] 5a 85 [2] 41 83 [2] 5d 84 [2] 41 ab }

  condition:
    any of them
}