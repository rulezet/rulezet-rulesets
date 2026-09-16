rule TTP_XOR_QUAD_CurrentVersionRun_2c0c {
  strings:
    $key_2c0c = { 7f 63 [2] 5b 6d [2] 70 41 [2] 5e 63 [2] 4a 78 [2] 45 62 [2] 5b 7f [2] 59 7e [2] 42 78 [2] 5e 7f [2] 42 50 }

  condition:
    any of them
}