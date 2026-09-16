rule TTP_XOR_QUAD_CurrentVersionRun_4812 {
  strings:
    $key_4812 = { 1b 7d [2] 3f 73 [2] 14 5f [2] 3a 7d [2] 2e 66 [2] 21 7c [2] 3f 61 [2] 3d 60 [2] 26 66 [2] 3a 61 [2] 26 4e }

  condition:
    any of them
}