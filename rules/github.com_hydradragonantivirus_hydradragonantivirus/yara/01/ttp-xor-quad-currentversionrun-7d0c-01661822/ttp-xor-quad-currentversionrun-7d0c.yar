rule TTP_XOR_QUAD_CurrentVersionRun_7d0c {
  strings:
    $key_7d0c = { 2e 63 [2] 0a 6d [2] 21 41 [2] 0f 63 [2] 1b 78 [2] 14 62 [2] 0a 7f [2] 08 7e [2] 13 78 [2] 0f 7f [2] 13 50 }

  condition:
    any of them
}