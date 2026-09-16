rule TTP_XOR_QUAD_CurrentVersionRun_f95f {
  strings:
    $key_f95f = { aa 30 [2] 8e 3e [2] a5 12 [2] 8b 30 [2] 9f 2b [2] 90 31 [2] 8e 2c [2] 8c 2d [2] 97 2b [2] 8b 2c [2] 97 03 }

  condition:
    any of them
}