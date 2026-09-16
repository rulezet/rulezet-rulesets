rule TTP_XOR_QUAD_CurrentVersionRun_6213 {
  strings:
    $key_6213 = { 31 7c [2] 15 72 [2] 3e 5e [2] 10 7c [2] 04 67 [2] 0b 7d [2] 15 60 [2] 17 61 [2] 0c 67 [2] 10 60 [2] 0c 4f }

  condition:
    any of them
}