rule TTP_XOR_QUAD_CurrentVersionRun_3e12 {
  strings:
    $key_3e12 = { 6d 7d [2] 49 73 [2] 62 5f [2] 4c 7d [2] 58 66 [2] 57 7c [2] 49 61 [2] 4b 60 [2] 50 66 [2] 4c 61 [2] 50 4e }

  condition:
    any of them
}