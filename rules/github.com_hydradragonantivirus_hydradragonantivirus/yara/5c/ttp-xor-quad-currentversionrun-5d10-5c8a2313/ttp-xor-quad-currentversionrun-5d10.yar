rule TTP_XOR_QUAD_CurrentVersionRun_5d10 {
  strings:
    $key_5d10 = { 0e 7f [2] 2a 71 [2] 01 5d [2] 2f 7f [2] 3b 64 [2] 34 7e [2] 2a 63 [2] 28 62 [2] 33 64 [2] 2f 63 [2] 33 4c }

  condition:
    any of them
}