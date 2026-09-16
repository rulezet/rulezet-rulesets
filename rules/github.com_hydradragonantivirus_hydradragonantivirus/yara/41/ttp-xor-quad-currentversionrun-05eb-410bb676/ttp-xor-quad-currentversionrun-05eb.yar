rule TTP_XOR_QUAD_CurrentVersionRun_05eb {
  strings:
    $key_05eb = { 56 84 [2] 72 8a [2] 59 a6 [2] 77 84 [2] 63 9f [2] 6c 85 [2] 72 98 [2] 70 99 [2] 6b 9f [2] 77 98 [2] 6b b7 }

  condition:
    any of them
}