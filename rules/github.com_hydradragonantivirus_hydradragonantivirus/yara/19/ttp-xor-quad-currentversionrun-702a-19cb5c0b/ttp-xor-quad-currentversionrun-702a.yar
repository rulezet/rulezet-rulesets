rule TTP_XOR_QUAD_CurrentVersionRun_702a {
  strings:
    $key_702a = { 23 45 [2] 07 4b [2] 2c 67 [2] 02 45 [2] 16 5e [2] 19 44 [2] 07 59 [2] 05 58 [2] 1e 5e [2] 02 59 [2] 1e 76 }

  condition:
    any of them
}