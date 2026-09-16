rule TTP_XOR_QUAD_CurrentVersionRun_3a1d {
  strings:
    $key_3a1d = { 69 72 [2] 4d 7c [2] 66 50 [2] 48 72 [2] 5c 69 [2] 53 73 [2] 4d 6e [2] 4f 6f [2] 54 69 [2] 48 6e [2] 54 41 }

  condition:
    any of them
}