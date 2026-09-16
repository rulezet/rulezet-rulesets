rule TTP_XOR_QUAD_CurrentVersionRun_0213 {
  strings:
    $key_0213 = { 51 7c [2] 75 72 [2] 5e 5e [2] 70 7c [2] 64 67 [2] 6b 7d [2] 75 60 [2] 77 61 [2] 6c 67 [2] 70 60 [2] 6c 4f }

  condition:
    any of them
}