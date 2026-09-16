rule TTP_XOR_QUAD_CurrentVersionRun_3857 {
  strings:
    $key_3857 = { 6b 38 [2] 4f 36 [2] 64 1a [2] 4a 38 [2] 5e 23 [2] 51 39 [2] 4f 24 [2] 4d 25 [2] 56 23 [2] 4a 24 [2] 56 0b }

  condition:
    any of them
}