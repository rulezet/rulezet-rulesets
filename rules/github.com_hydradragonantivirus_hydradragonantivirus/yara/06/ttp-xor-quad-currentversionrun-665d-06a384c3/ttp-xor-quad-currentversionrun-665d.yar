rule TTP_XOR_QUAD_CurrentVersionRun_665d {
  strings:
    $key_665d = { 35 32 [2] 11 3c [2] 3a 10 [2] 14 32 [2] 00 29 [2] 0f 33 [2] 11 2e [2] 13 2f [2] 08 29 [2] 14 2e [2] 08 01 }

  condition:
    any of them
}