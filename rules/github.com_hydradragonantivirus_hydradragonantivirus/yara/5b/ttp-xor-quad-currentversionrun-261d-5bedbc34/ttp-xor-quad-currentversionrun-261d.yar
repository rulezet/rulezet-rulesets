rule TTP_XOR_QUAD_CurrentVersionRun_261d {
  strings:
    $key_261d = { 75 72 [2] 51 7c [2] 7a 50 [2] 54 72 [2] 40 69 [2] 4f 73 [2] 51 6e [2] 53 6f [2] 48 69 [2] 54 6e [2] 48 41 }

  condition:
    any of them
}