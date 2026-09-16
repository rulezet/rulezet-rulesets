rule TTP_XOR_QUAD_CurrentVersionRun_3b12 {
  strings:
    $key_3b12 = { 68 7d [2] 4c 73 [2] 67 5f [2] 49 7d [2] 5d 66 [2] 52 7c [2] 4c 61 [2] 4e 60 [2] 55 66 [2] 49 61 [2] 55 4e }

  condition:
    any of them
}