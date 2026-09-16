rule TTP_XOR_QUAD_CurrentVersionRun_3923 {
  strings:
    $key_3923 = { 6a 4c [2] 4e 42 [2] 65 6e [2] 4b 4c [2] 5f 57 [2] 50 4d [2] 4e 50 [2] 4c 51 [2] 57 57 [2] 4b 50 [2] 57 7f }

  condition:
    any of them
}