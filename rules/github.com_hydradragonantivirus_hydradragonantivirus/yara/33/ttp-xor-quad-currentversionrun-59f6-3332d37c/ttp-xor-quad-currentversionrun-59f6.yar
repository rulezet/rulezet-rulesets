rule TTP_XOR_QUAD_CurrentVersionRun_59f6 {
  strings:
    $key_59f6 = { 0a 99 [2] 2e 97 [2] 05 bb [2] 2b 99 [2] 3f 82 [2] 30 98 [2] 2e 85 [2] 2c 84 [2] 37 82 [2] 2b 85 [2] 37 aa }

  condition:
    any of them
}