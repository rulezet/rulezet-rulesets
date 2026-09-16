rule TTP_XOR_QUAD_CurrentVersionRun_5900 {
  strings:
    $key_5900 = { 0a 6f [2] 2e 61 [2] 05 4d [2] 2b 6f [2] 3f 74 [2] 30 6e [2] 2e 73 [2] 2c 72 [2] 37 74 [2] 2b 73 [2] 37 5c }

  condition:
    any of them
}