rule TTP_XOR_QUAD_CurrentVersionRun_7d0d {
  strings:
    $key_7d0d = { 2e 62 [2] 0a 6c [2] 21 40 [2] 0f 62 [2] 1b 79 [2] 14 63 [2] 0a 7e [2] 08 7f [2] 13 79 [2] 0f 7e [2] 13 51 }

  condition:
    any of them
}