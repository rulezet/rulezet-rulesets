rule TTP_XOR_QUAD_CurrentVersionRun_4deb {
  strings:
    $key_4deb = { 1e 84 [2] 3a 8a [2] 11 a6 [2] 3f 84 [2] 2b 9f [2] 24 85 [2] 3a 98 [2] 38 99 [2] 23 9f [2] 3f 98 [2] 23 b7 }

  condition:
    any of them
}