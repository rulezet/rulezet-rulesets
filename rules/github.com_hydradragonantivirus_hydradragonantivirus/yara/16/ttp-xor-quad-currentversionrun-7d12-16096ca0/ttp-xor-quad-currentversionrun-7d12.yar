rule TTP_XOR_QUAD_CurrentVersionRun_7d12 {
  strings:
    $key_7d12 = { 2e 7d [2] 0a 73 [2] 21 5f [2] 0f 7d [2] 1b 66 [2] 14 7c [2] 0a 61 [2] 08 60 [2] 13 66 [2] 0f 61 [2] 13 4e }

  condition:
    any of them
}