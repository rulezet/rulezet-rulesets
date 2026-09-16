rule TTP_XOR_QUAD_CurrentVersionRun_660c {
  strings:
    $key_660c = { 35 63 [2] 11 6d [2] 3a 41 [2] 14 63 [2] 00 78 [2] 0f 62 [2] 11 7f [2] 13 7e [2] 08 78 [2] 14 7f [2] 08 50 }

  condition:
    any of them
}