rule TTP_XOR_QUAD_CurrentVersionRun_2e7c {
  strings:
    $key_2e7c = { 7d 13 [2] 59 1d [2] 72 31 [2] 5c 13 [2] 48 08 [2] 47 12 [2] 59 0f [2] 5b 0e [2] 40 08 [2] 5c 0f [2] 40 20 }

  condition:
    any of them
}