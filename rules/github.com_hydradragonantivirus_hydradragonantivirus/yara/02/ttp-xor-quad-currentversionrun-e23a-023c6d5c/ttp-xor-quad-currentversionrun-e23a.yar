rule TTP_XOR_QUAD_CurrentVersionRun_e23a {
  strings:
    $key_e23a = { b1 55 [2] 95 5b [2] be 77 [2] 90 55 [2] 84 4e [2] 8b 54 [2] 95 49 [2] 97 48 [2] 8c 4e [2] 90 49 [2] 8c 66 }

  condition:
    any of them
}