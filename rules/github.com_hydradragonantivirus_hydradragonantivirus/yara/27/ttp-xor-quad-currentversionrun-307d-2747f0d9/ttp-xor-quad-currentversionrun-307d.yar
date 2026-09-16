rule TTP_XOR_QUAD_CurrentVersionRun_307d {
  strings:
    $key_307d = { 63 12 [2] 47 1c [2] 6c 30 [2] 42 12 [2] 56 09 [2] 59 13 [2] 47 0e [2] 45 0f [2] 5e 09 [2] 42 0e [2] 5e 21 }

  condition:
    any of them
}