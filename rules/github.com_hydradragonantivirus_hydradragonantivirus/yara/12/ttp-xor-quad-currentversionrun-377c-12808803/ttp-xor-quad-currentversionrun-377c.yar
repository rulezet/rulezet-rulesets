rule TTP_XOR_QUAD_CurrentVersionRun_377c {
  strings:
    $key_377c = { 64 13 [2] 40 1d [2] 6b 31 [2] 45 13 [2] 51 08 [2] 5e 12 [2] 40 0f [2] 42 0e [2] 59 08 [2] 45 0f [2] 59 20 }

  condition:
    any of them
}