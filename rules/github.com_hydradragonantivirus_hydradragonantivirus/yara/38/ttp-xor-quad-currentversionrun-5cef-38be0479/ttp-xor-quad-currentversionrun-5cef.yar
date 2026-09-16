rule TTP_XOR_QUAD_CurrentVersionRun_5cef {
  strings:
    $key_5cef = { 0f 80 [2] 2b 8e [2] 00 a2 [2] 2e 80 [2] 3a 9b [2] 35 81 [2] 2b 9c [2] 29 9d [2] 32 9b [2] 2e 9c [2] 32 b3 }

  condition:
    any of them
}