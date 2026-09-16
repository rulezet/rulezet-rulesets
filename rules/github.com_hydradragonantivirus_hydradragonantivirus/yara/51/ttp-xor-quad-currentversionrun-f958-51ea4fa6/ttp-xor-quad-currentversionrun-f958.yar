rule TTP_XOR_QUAD_CurrentVersionRun_f958 {
  strings:
    $key_f958 = { aa 37 [2] 8e 39 [2] a5 15 [2] 8b 37 [2] 9f 2c [2] 90 36 [2] 8e 2b [2] 8c 2a [2] 97 2c [2] 8b 2b [2] 97 04 }

  condition:
    any of them
}