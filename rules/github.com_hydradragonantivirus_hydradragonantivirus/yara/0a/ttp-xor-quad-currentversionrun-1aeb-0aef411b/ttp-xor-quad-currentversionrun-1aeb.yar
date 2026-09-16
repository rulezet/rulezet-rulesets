rule TTP_XOR_QUAD_CurrentVersionRun_1aeb {
  strings:
    $key_1aeb = { 49 84 [2] 6d 8a [2] 46 a6 [2] 68 84 [2] 7c 9f [2] 73 85 [2] 6d 98 [2] 6f 99 [2] 74 9f [2] 68 98 [2] 74 b7 }

  condition:
    any of them
}