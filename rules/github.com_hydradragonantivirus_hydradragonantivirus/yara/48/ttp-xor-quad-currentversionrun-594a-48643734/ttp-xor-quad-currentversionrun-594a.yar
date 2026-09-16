rule TTP_XOR_QUAD_CurrentVersionRun_594a {
  strings:
    $key_594a = { 0a 25 [2] 2e 2b [2] 05 07 [2] 2b 25 [2] 3f 3e [2] 30 24 [2] 2e 39 [2] 2c 38 [2] 37 3e [2] 2b 39 [2] 37 16 }

  condition:
    any of them
}