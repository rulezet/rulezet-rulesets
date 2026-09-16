rule TTP_XOR_QUAD_CurrentVersionRun_2c3f {
  strings:
    $key_2c3f = { 7f 50 [2] 5b 5e [2] 70 72 [2] 5e 50 [2] 4a 4b [2] 45 51 [2] 5b 4c [2] 59 4d [2] 42 4b [2] 5e 4c [2] 42 63 }

  condition:
    any of them
}