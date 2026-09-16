rule TTP_XOR_QUAD_CurrentVersionRun_071d {
  strings:
    $key_071d = { 54 72 [2] 70 7c [2] 5b 50 [2] 75 72 [2] 61 69 [2] 6e 73 [2] 70 6e [2] 72 6f [2] 69 69 [2] 75 6e [2] 69 41 }

  condition:
    any of them
}