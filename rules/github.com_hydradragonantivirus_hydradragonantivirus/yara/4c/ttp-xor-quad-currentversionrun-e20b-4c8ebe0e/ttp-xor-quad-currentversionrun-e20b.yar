rule TTP_XOR_QUAD_CurrentVersionRun_e20b {
  strings:
    $key_e20b = { b1 64 [2] 95 6a [2] be 46 [2] 90 64 [2] 84 7f [2] 8b 65 [2] 95 78 [2] 97 79 [2] 8c 7f [2] 90 78 [2] 8c 57 }

  condition:
    any of them
}