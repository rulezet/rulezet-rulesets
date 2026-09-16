rule TTP_XOR_QUAD_CurrentVersionRun_452a {
  strings:
    $key_452a = { 16 45 [2] 32 4b [2] 19 67 [2] 37 45 [2] 23 5e [2] 2c 44 [2] 32 59 [2] 30 58 [2] 2b 5e [2] 37 59 [2] 2b 76 }

  condition:
    any of them
}