rule TTP_XOR_QUAD_CurrentVersionRun_6d12 {
  strings:
    $key_6d12 = { 3e 7d [2] 1a 73 [2] 31 5f [2] 1f 7d [2] 0b 66 [2] 04 7c [2] 1a 61 [2] 18 60 [2] 03 66 [2] 1f 61 [2] 03 4e }

  condition:
    any of them
}