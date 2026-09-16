rule TTP_XOR_QUAD_CurrentVersionRun_5deb {
  strings:
    $key_5deb = { 0e 84 [2] 2a 8a [2] 01 a6 [2] 2f 84 [2] 3b 9f [2] 34 85 [2] 2a 98 [2] 28 99 [2] 33 9f [2] 2f 98 [2] 33 b7 }

  condition:
    any of them
}