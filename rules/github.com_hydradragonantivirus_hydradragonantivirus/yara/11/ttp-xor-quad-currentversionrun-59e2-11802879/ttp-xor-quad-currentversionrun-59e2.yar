rule TTP_XOR_QUAD_CurrentVersionRun_59e2 {
  strings:
    $key_59e2 = { 0a 8d [2] 2e 83 [2] 05 af [2] 2b 8d [2] 3f 96 [2] 30 8c [2] 2e 91 [2] 2c 90 [2] 37 96 [2] 2b 91 [2] 37 be }

  condition:
    any of them
}