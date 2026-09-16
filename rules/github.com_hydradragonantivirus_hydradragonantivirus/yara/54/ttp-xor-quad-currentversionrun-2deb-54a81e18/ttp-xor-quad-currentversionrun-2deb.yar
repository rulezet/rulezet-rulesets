rule TTP_XOR_QUAD_CurrentVersionRun_2deb {
  strings:
    $key_2deb = { 7e 84 [2] 5a 8a [2] 71 a6 [2] 5f 84 [2] 4b 9f [2] 44 85 [2] 5a 98 [2] 58 99 [2] 43 9f [2] 5f 98 [2] 43 b7 }

  condition:
    any of them
}