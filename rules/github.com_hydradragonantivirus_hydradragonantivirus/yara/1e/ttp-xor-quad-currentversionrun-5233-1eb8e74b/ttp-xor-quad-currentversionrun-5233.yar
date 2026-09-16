rule TTP_XOR_QUAD_CurrentVersionRun_5233 {
  strings:
    $key_5233 = { 01 5c [2] 25 52 [2] 0e 7e [2] 20 5c [2] 34 47 [2] 3b 5d [2] 25 40 [2] 27 41 [2] 3c 47 [2] 20 40 [2] 3c 6f }

  condition:
    any of them
}