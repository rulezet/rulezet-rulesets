rule TTP_XOR_QUAD_CurrentVersionRun_7533 {
  strings:
    $key_7533 = { 26 5c [2] 02 52 [2] 29 7e [2] 07 5c [2] 13 47 [2] 1c 5d [2] 02 40 [2] 00 41 [2] 1b 47 [2] 07 40 [2] 1b 6f }

  condition:
    any of them
}