rule TTP_XOR_QUAD_CurrentVersionRun_2c2e {
  strings:
    $key_2c2e = { 7f 41 [2] 5b 4f [2] 70 63 [2] 5e 41 [2] 4a 5a [2] 45 40 [2] 5b 5d [2] 59 5c [2] 42 5a [2] 5e 5d [2] 42 72 }

  condition:
    any of them
}