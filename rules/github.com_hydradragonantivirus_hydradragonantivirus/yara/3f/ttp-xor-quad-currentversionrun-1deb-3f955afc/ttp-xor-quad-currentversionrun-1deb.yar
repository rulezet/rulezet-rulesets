rule TTP_XOR_QUAD_CurrentVersionRun_1deb {
  strings:
    $key_1deb = { 4e 84 [2] 6a 8a [2] 41 a6 [2] 6f 84 [2] 7b 9f [2] 74 85 [2] 6a 98 [2] 68 99 [2] 73 9f [2] 6f 98 [2] 73 b7 }

  condition:
    any of them
}