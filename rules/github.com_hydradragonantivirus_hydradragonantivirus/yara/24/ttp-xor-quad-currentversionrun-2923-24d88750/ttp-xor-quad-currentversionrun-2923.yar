rule TTP_XOR_QUAD_CurrentVersionRun_2923 {
  strings:
    $key_2923 = { 7a 4c [2] 5e 42 [2] 75 6e [2] 5b 4c [2] 4f 57 [2] 40 4d [2] 5e 50 [2] 5c 51 [2] 47 57 [2] 5b 50 [2] 47 7f }

  condition:
    any of them
}