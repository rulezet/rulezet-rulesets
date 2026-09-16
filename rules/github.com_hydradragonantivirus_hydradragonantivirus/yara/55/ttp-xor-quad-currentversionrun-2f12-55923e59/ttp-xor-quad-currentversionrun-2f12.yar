rule TTP_XOR_QUAD_CurrentVersionRun_2f12 {
  strings:
    $key_2f12 = { 7c 7d [2] 58 73 [2] 73 5f [2] 5d 7d [2] 49 66 [2] 46 7c [2] 58 61 [2] 5a 60 [2] 41 66 [2] 5d 61 [2] 41 4e }

  condition:
    any of them
}