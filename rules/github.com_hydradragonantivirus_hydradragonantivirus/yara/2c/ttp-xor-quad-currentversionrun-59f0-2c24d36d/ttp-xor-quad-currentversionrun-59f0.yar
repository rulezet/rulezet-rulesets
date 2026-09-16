rule TTP_XOR_QUAD_CurrentVersionRun_59f0 {
  strings:
    $key_59f0 = { 0a 9f [2] 2e 91 [2] 05 bd [2] 2b 9f [2] 3f 84 [2] 30 9e [2] 2e 83 [2] 2c 82 [2] 37 84 [2] 2b 83 [2] 37 ac }

  condition:
    any of them
}