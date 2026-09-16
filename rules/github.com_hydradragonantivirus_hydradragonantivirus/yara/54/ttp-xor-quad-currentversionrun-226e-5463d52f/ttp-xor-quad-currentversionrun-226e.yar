rule TTP_XOR_QUAD_CurrentVersionRun_226e {
  strings:
    $key_226e = { 71 01 [2] 55 0f [2] 7e 23 [2] 50 01 [2] 44 1a [2] 4b 00 [2] 55 1d [2] 57 1c [2] 4c 1a [2] 50 1d [2] 4c 32 }

  condition:
    any of them
}