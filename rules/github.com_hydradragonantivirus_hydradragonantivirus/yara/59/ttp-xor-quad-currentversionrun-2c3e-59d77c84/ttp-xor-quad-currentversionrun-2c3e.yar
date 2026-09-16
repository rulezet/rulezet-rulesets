rule TTP_XOR_QUAD_CurrentVersionRun_2c3e {
  strings:
    $key_2c3e = { 7f 51 [2] 5b 5f [2] 70 73 [2] 5e 51 [2] 4a 4a [2] 45 50 [2] 5b 4d [2] 59 4c [2] 42 4a [2] 5e 4d [2] 42 62 }

  condition:
    any of them
}