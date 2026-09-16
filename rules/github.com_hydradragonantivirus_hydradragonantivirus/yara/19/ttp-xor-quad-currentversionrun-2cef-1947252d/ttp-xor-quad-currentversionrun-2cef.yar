rule TTP_XOR_QUAD_CurrentVersionRun_2cef {
  strings:
    $key_2cef = { 7f 80 [2] 5b 8e [2] 70 a2 [2] 5e 80 [2] 4a 9b [2] 45 81 [2] 5b 9c [2] 59 9d [2] 42 9b [2] 5e 9c [2] 42 b3 }

  condition:
    any of them
}