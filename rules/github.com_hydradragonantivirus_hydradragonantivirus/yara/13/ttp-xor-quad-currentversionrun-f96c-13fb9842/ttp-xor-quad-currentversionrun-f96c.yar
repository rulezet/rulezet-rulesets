rule TTP_XOR_QUAD_CurrentVersionRun_f96c {
  strings:
    $key_f96c = { aa 03 [2] 8e 0d [2] a5 21 [2] 8b 03 [2] 9f 18 [2] 90 02 [2] 8e 1f [2] 8c 1e [2] 97 18 [2] 8b 1f [2] 97 30 }

  condition:
    any of them
}