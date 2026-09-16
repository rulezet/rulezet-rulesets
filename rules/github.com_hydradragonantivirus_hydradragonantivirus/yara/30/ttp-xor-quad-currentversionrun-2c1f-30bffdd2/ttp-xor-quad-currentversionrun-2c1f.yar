rule TTP_XOR_QUAD_CurrentVersionRun_2c1f {
  strings:
    $key_2c1f = { 7f 70 [2] 5b 7e [2] 70 52 [2] 5e 70 [2] 4a 6b [2] 45 71 [2] 5b 6c [2] 59 6d [2] 42 6b [2] 5e 6c [2] 42 43 }

  condition:
    any of them
}