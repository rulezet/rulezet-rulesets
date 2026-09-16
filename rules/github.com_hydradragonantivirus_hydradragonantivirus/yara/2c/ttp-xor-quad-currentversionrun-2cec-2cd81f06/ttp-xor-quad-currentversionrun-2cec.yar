rule TTP_XOR_QUAD_CurrentVersionRun_2cec {
  strings:
    $key_2cec = { 7f 83 [2] 5b 8d [2] 70 a1 [2] 5e 83 [2] 4a 98 [2] 45 82 [2] 5b 9f [2] 59 9e [2] 42 98 [2] 5e 9f [2] 42 b0 }

  condition:
    any of them
}