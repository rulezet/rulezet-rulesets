rule TTP_XOR_QUAD_CurrentVersionRun_6deb {
  strings:
    $key_6deb = { 3e 84 [2] 1a 8a [2] 31 a6 [2] 1f 84 [2] 0b 9f [2] 04 85 [2] 1a 98 [2] 18 99 [2] 03 9f [2] 1f 98 [2] 03 b7 }

  condition:
    any of them
}