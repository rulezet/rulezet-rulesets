rule TTP_XOR_QUAD_CurrentVersionRun_327d {
  strings:
    $key_327d = { 61 12 [2] 45 1c [2] 6e 30 [2] 40 12 [2] 54 09 [2] 5b 13 [2] 45 0e [2] 47 0f [2] 5c 09 [2] 40 0e [2] 5c 21 }

  condition:
    any of them
}