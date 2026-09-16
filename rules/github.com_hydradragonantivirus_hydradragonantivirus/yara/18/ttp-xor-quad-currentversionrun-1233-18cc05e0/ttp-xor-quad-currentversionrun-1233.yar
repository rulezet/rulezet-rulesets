rule TTP_XOR_QUAD_CurrentVersionRun_1233 {
  strings:
    $key_1233 = { 41 5c [2] 65 52 [2] 4e 7e [2] 60 5c [2] 74 47 [2] 7b 5d [2] 65 40 [2] 67 41 [2] 7c 47 [2] 60 40 [2] 7c 6f }

  condition:
    any of them
}