rule TTP_XOR_QUAD_CurrentVersionRun_7f4a {
  strings:
    $key_7f4a = { 2c 25 [2] 08 2b [2] 23 07 [2] 0d 25 [2] 19 3e [2] 16 24 [2] 08 39 [2] 0a 38 [2] 11 3e [2] 0d 39 [2] 11 16 }

  condition:
    any of them
}