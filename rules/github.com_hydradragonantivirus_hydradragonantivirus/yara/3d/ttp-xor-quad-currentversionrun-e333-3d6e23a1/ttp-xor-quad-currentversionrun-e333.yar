rule TTP_XOR_QUAD_CurrentVersionRun_e333 {
  strings:
    $key_e333 = { b0 5c [2] 94 52 [2] bf 7e [2] 91 5c [2] 85 47 [2] 8a 5d [2] 94 40 [2] 96 41 [2] 8d 47 [2] 91 40 [2] 8d 6f }

  condition:
    any of them
}