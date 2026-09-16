rule TTP_XOR_QUAD_CurrentVersionRun_e26d {
  strings:
    $key_e26d = { b1 02 [2] 95 0c [2] be 20 [2] 90 02 [2] 84 19 [2] 8b 03 [2] 95 1e [2] 97 1f [2] 8c 19 [2] 90 1e [2] 8c 31 }

  condition:
    any of them
}