rule TTP_XOR_QUAD_CurrentVersionRun_f167 {
  strings:
    $key_f167 = { a2 08 [2] 86 06 [2] ad 2a [2] 83 08 [2] 97 13 [2] 98 09 [2] 86 14 [2] 84 15 [2] 9f 13 [2] 83 14 [2] 9f 3b }

  condition:
    any of them
}