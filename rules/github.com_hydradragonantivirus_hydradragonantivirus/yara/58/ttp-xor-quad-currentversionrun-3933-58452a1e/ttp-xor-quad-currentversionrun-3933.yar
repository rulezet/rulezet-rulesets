rule TTP_XOR_QUAD_CurrentVersionRun_3933 {
  strings:
    $key_3933 = { 6a 5c [2] 4e 52 [2] 65 7e [2] 4b 5c [2] 5f 47 [2] 50 5d [2] 4e 40 [2] 4c 41 [2] 57 47 [2] 4b 40 [2] 57 6f }

  condition:
    any of them
}