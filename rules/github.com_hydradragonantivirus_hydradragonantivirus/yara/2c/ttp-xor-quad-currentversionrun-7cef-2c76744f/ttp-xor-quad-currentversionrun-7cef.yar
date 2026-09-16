rule TTP_XOR_QUAD_CurrentVersionRun_7cef {
  strings:
    $key_7cef = { 2f 80 [2] 0b 8e [2] 20 a2 [2] 0e 80 [2] 1a 9b [2] 15 81 [2] 0b 9c [2] 09 9d [2] 12 9b [2] 0e 9c [2] 12 b3 }

  condition:
    any of them
}