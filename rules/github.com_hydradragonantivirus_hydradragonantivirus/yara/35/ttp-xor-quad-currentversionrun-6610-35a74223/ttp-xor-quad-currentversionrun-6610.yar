rule TTP_XOR_QUAD_CurrentVersionRun_6610 {
  strings:
    $key_6610 = { 35 7f [2] 11 71 [2] 3a 5d [2] 14 7f [2] 00 64 [2] 0f 7e [2] 11 63 [2] 13 62 [2] 08 64 [2] 14 63 [2] 08 4c }

  condition:
    any of them
}