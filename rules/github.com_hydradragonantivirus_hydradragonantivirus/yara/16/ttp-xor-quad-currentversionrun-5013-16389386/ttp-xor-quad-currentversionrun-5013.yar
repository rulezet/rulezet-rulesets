rule TTP_XOR_QUAD_CurrentVersionRun_5013 {
  strings:
    $key_5013 = { 03 7c [2] 27 72 [2] 0c 5e [2] 22 7c [2] 36 67 [2] 39 7d [2] 27 60 [2] 25 61 [2] 3e 67 [2] 22 60 [2] 3e 4f }

  condition:
    any of them
}