rule TTP_XOR_QUAD_CurrentVersionRun_2813 {
  strings:
    $key_2813 = { 7b 7c [2] 5f 72 [2] 74 5e [2] 5a 7c [2] 4e 67 [2] 41 7d [2] 5f 60 [2] 5d 61 [2] 46 67 [2] 5a 60 [2] 46 4f }

  condition:
    any of them
}