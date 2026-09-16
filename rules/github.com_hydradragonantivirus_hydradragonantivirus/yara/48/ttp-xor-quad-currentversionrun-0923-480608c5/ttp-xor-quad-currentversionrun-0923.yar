rule TTP_XOR_QUAD_CurrentVersionRun_0923 {
  strings:
    $key_0923 = { 5a 4c [2] 7e 42 [2] 55 6e [2] 7b 4c [2] 6f 57 [2] 60 4d [2] 7e 50 [2] 7c 51 [2] 67 57 [2] 7b 50 [2] 67 7f }

  condition:
    any of them
}