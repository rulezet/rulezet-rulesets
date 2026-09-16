rule TTP_XOR_QUAD_CurrentVersionRun_2c1e {
  strings:
    $key_2c1e = { 7f 71 [2] 5b 7f [2] 70 53 [2] 5e 71 [2] 4a 6a [2] 45 70 [2] 5b 6d [2] 59 6c [2] 42 6a [2] 5e 6d [2] 42 42 }

  condition:
    any of them
}