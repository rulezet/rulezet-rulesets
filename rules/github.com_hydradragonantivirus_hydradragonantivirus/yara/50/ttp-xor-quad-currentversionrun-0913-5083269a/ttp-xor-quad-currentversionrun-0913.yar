rule TTP_XOR_QUAD_CurrentVersionRun_0913 {
  strings:
    $key_0913 = { 5a 7c [2] 7e 72 [2] 55 5e [2] 7b 7c [2] 6f 67 [2] 60 7d [2] 7e 60 [2] 7c 61 [2] 67 67 [2] 7b 60 [2] 67 4f }

  condition:
    any of them
}