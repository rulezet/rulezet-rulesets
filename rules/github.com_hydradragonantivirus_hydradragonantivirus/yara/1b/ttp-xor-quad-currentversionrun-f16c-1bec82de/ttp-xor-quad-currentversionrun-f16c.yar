rule TTP_XOR_QUAD_CurrentVersionRun_f16c {
  strings:
    $key_f16c = { a2 03 [2] 86 0d [2] ad 21 [2] 83 03 [2] 97 18 [2] 98 02 [2] 86 1f [2] 84 1e [2] 9f 18 [2] 83 1f [2] 9f 30 }

  condition:
    any of them
}