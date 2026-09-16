rule TTP_XOR_QUAD_CurrentVersionRun_59fd {
  strings:
    $key_59fd = { 0a 92 [2] 2e 9c [2] 05 b0 [2] 2b 92 [2] 3f 89 [2] 30 93 [2] 2e 8e [2] 2c 8f [2] 37 89 [2] 2b 8e [2] 37 a1 }

  condition:
    any of them
}