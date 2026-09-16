rule TTP_XOR_QUAD_CurrentVersionRun_2cff {
  strings:
    $key_2cff = { 7f 90 [2] 5b 9e [2] 70 b2 [2] 5e 90 [2] 4a 8b [2] 45 91 [2] 5b 8c [2] 59 8d [2] 42 8b [2] 5e 8c [2] 42 a3 }

  condition:
    any of them
}