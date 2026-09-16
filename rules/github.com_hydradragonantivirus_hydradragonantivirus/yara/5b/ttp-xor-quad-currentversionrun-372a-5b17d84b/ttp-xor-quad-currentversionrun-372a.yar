rule TTP_XOR_QUAD_CurrentVersionRun_372a {
  strings:
    $key_372a = { 64 45 [2] 40 4b [2] 6b 67 [2] 45 45 [2] 51 5e [2] 5e 44 [2] 40 59 [2] 42 58 [2] 59 5e [2] 45 59 [2] 59 76 }

  condition:
    any of them
}