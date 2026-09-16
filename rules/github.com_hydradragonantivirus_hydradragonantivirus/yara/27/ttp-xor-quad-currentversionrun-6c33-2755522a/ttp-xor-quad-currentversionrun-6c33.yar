rule TTP_XOR_QUAD_CurrentVersionRun_6c33 {
  strings:
    $key_6c33 = { 3f 5c [2] 1b 52 [2] 30 7e [2] 1e 5c [2] 0a 47 [2] 05 5d [2] 1b 40 [2] 19 41 [2] 02 47 [2] 1e 40 [2] 02 6f }

  condition:
    any of them
}