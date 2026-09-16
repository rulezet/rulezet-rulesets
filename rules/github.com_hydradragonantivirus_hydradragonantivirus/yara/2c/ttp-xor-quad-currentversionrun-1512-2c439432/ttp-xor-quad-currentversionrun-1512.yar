rule TTP_XOR_QUAD_CurrentVersionRun_1512 {
  strings:
    $key_1512 = { 46 7d [2] 62 73 [2] 49 5f [2] 67 7d [2] 73 66 [2] 7c 7c [2] 62 61 [2] 60 60 [2] 7b 66 [2] 67 61 [2] 7b 4e }

  condition:
    any of them
}