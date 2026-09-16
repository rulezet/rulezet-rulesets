rule TTP_XOR_QUAD_CurrentVersionRun_0beb {
  strings:
    $key_0beb = { 58 84 [2] 7c 8a [2] 57 a6 [2] 79 84 [2] 6d 9f [2] 62 85 [2] 7c 98 [2] 7e 99 [2] 65 9f [2] 79 98 [2] 65 b7 }

  condition:
    any of them
}