rule TTP_XOR_QUAD_CurrentVersionRun_5703 {
  strings:
    $key_5703 = { 04 6c [2] 20 62 [2] 0b 4e [2] 25 6c [2] 31 77 [2] 3e 6d [2] 20 70 [2] 22 71 [2] 39 77 [2] 25 70 [2] 39 5f }

  condition:
    any of them
}