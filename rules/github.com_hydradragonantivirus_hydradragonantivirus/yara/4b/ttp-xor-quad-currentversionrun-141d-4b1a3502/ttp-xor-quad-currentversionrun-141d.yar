rule TTP_XOR_QUAD_CurrentVersionRun_141d {
  strings:
    $key_141d = { 47 72 [2] 63 7c [2] 48 50 [2] 66 72 [2] 72 69 [2] 7d 73 [2] 63 6e [2] 61 6f [2] 7a 69 [2] 66 6e [2] 7a 41 }

  condition:
    any of them
}