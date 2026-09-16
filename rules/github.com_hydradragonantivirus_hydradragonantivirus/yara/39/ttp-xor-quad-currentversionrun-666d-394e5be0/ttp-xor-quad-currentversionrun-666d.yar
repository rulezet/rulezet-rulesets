rule TTP_XOR_QUAD_CurrentVersionRun_666d {
  strings:
    $key_666d = { 35 02 [2] 11 0c [2] 3a 20 [2] 14 02 [2] 00 19 [2] 0f 03 [2] 11 1e [2] 13 1f [2] 08 19 [2] 14 1e [2] 08 31 }

  condition:
    any of them
}