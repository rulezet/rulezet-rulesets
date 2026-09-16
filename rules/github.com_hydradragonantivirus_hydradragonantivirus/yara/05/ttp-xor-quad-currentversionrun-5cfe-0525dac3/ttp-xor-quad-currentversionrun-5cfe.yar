rule TTP_XOR_QUAD_CurrentVersionRun_5cfe {
  strings:
    $key_5cfe = { 0f 91 [2] 2b 9f [2] 00 b3 [2] 2e 91 [2] 3a 8a [2] 35 90 [2] 2b 8d [2] 29 8c [2] 32 8a [2] 2e 8d [2] 32 a2 }

  condition:
    any of them
}