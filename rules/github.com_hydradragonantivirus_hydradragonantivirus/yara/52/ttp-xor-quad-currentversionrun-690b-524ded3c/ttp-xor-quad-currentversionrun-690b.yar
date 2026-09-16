rule TTP_XOR_QUAD_CurrentVersionRun_690b {
  strings:
    $key_690b = { 3a 64 [2] 1e 6a [2] 35 46 [2] 1b 64 [2] 0f 7f [2] 00 65 [2] 1e 78 [2] 1c 79 [2] 07 7f [2] 1b 78 [2] 07 57 }

  condition:
    any of them
}