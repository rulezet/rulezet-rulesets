rule TTP_XOR_QUAD_CurrentVersionRun_2ceb {
  strings:
    $key_2ceb = { 7f 84 [2] 5b 8a [2] 70 a6 [2] 5e 84 [2] 4a 9f [2] 45 85 [2] 5b 98 [2] 59 99 [2] 42 9f [2] 5e 98 [2] 42 b7 }

  condition:
    any of them
}