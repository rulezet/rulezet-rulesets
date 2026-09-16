rule TTP_XOR_QUAD_CurrentVersionRun_7f3c {
  strings:
    $key_7f3c = { 2c 53 [2] 08 5d [2] 23 71 [2] 0d 53 [2] 19 48 [2] 16 52 [2] 08 4f [2] 0a 4e [2] 11 48 [2] 0d 4f [2] 11 60 }

  condition:
    any of them
}