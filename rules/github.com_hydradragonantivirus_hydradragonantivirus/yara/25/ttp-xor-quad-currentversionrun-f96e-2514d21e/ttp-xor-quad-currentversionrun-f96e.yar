rule TTP_XOR_QUAD_CurrentVersionRun_f96e {
  strings:
    $key_f96e = { aa 01 [2] 8e 0f [2] a5 23 [2] 8b 01 [2] 9f 1a [2] 90 00 [2] 8e 1d [2] 8c 1c [2] 97 1a [2] 8b 1d [2] 97 32 }

  condition:
    any of them
}