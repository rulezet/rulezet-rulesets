rule TTP_XOR_QUAD_CurrentVersionRun_e26c {
  strings:
    $key_e26c = { b1 03 [2] 95 0d [2] be 21 [2] 90 03 [2] 84 18 [2] 8b 02 [2] 95 1f [2] 97 1e [2] 8c 18 [2] 90 1f [2] 8c 30 }

  condition:
    any of them
}