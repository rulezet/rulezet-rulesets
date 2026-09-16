rule TTP_XOR_QUAD_CurrentVersionRun_6aeb {
  strings:
    $key_6aeb = { 39 84 [2] 1d 8a [2] 36 a6 [2] 18 84 [2] 0c 9f [2] 03 85 [2] 1d 98 [2] 1f 99 [2] 04 9f [2] 18 98 [2] 04 b7 }

  condition:
    any of them
}