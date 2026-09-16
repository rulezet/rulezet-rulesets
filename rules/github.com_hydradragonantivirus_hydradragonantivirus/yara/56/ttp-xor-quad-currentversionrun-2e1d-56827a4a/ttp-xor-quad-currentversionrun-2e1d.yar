rule TTP_XOR_QUAD_CurrentVersionRun_2e1d {
  strings:
    $key_2e1d = { 7d 72 [2] 59 7c [2] 72 50 [2] 5c 72 [2] 48 69 [2] 47 73 [2] 59 6e [2] 5b 6f [2] 40 69 [2] 5c 6e [2] 40 41 }

  condition:
    any of them
}