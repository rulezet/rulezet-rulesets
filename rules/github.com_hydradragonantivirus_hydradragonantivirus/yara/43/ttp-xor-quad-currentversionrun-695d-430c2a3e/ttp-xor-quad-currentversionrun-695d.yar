rule TTP_XOR_QUAD_CurrentVersionRun_695d {
  strings:
    $key_695d = { 3a 32 [2] 1e 3c [2] 35 10 [2] 1b 32 [2] 0f 29 [2] 00 33 [2] 1e 2e [2] 1c 2f [2] 07 29 [2] 1b 2e [2] 07 01 }

  condition:
    any of them
}