rule TTP_XOR_QUAD_CurrentVersionRun_7a7f {
  strings:
    $key_7a7f = { 29 10 [2] 0d 1e [2] 26 32 [2] 08 10 [2] 1c 0b [2] 13 11 [2] 0d 0c [2] 0f 0d [2] 14 0b [2] 08 0c [2] 14 23 }

  condition:
    any of them
}