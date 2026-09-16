rule TTP_XOR_QUAD_CurrentVersionRun_59e0 {
  strings:
    $key_59e0 = { 0a 8f [2] 2e 81 [2] 05 ad [2] 2b 8f [2] 3f 94 [2] 30 8e [2] 2e 93 [2] 2c 92 [2] 37 94 [2] 2b 93 [2] 37 bc }

  condition:
    any of them
}