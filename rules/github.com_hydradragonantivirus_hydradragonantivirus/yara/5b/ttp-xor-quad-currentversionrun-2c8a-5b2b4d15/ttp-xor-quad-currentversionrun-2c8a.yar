rule TTP_XOR_QUAD_CurrentVersionRun_2c8a {
  strings:
    $key_2c8a = { 7f e5 [2] 5b eb [2] 70 c7 [2] 5e e5 [2] 4a fe [2] 45 e4 [2] 5b f9 [2] 59 f8 [2] 42 fe [2] 5e f9 [2] 42 d6 }

  condition:
    any of them
}