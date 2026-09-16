rule TTP_XOR_QUAD_CurrentVersionRun_e24a {
  strings:
    $key_e24a = { b1 25 [2] 95 2b [2] be 07 [2] 90 25 [2] 84 3e [2] 8b 24 [2] 95 39 [2] 97 38 [2] 8c 3e [2] 90 39 [2] 8c 16 }

  condition:
    any of them
}