rule TTP_XOR_QUAD_CurrentVersionRun_59e5 {
  strings:
    $key_59e5 = { 0a 8a [2] 2e 84 [2] 05 a8 [2] 2b 8a [2] 3f 91 [2] 30 8b [2] 2e 96 [2] 2c 97 [2] 37 91 [2] 2b 96 [2] 37 b9 }

  condition:
    any of them
}