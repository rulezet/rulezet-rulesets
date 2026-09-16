rule TTP_XOR_QUAD_CurrentVersionRun_7933 {
  strings:
    $key_7933 = { 2a 5c [2] 0e 52 [2] 25 7e [2] 0b 5c [2] 1f 47 [2] 10 5d [2] 0e 40 [2] 0c 41 [2] 17 47 [2] 0b 40 [2] 17 6f }

  condition:
    any of them
}