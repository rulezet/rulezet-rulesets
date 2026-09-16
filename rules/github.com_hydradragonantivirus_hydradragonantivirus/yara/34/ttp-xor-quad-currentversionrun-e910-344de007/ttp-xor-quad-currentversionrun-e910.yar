rule TTP_XOR_QUAD_CurrentVersionRun_e910 {
  strings:
    $key_e910 = { ba 7f [2] 9e 71 [2] b5 5d [2] 9b 7f [2] 8f 64 [2] 80 7e [2] 9e 63 [2] 9c 62 [2] 87 64 [2] 9b 63 [2] 87 4c }

  condition:
    any of them
}