rule TTP_XOR_QUAD_CurrentVersionRun_0aeb {
  strings:
    $key_0aeb = { 59 84 [2] 7d 8a [2] 56 a6 [2] 78 84 [2] 6c 9f [2] 63 85 [2] 7d 98 [2] 7f 99 [2] 64 9f [2] 78 98 [2] 64 b7 }

  condition:
    any of them
}