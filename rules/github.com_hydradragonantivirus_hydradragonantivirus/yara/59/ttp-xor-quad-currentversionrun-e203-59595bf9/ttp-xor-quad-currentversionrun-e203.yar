rule TTP_XOR_QUAD_CurrentVersionRun_e203 {
  strings:
    $key_e203 = { b1 6c [2] 95 62 [2] be 4e [2] 90 6c [2] 84 77 [2] 8b 6d [2] 95 70 [2] 97 71 [2] 8c 77 [2] 90 70 [2] 8c 5f }

  condition:
    any of them
}