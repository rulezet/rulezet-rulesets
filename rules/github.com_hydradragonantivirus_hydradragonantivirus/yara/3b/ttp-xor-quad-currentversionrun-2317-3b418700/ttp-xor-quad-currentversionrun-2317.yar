rule TTP_XOR_QUAD_CurrentVersionRun_2317 {
  strings:
    $key_2317 = { 70 78 [2] 54 76 [2] 7f 5a [2] 51 78 [2] 45 63 [2] 4a 79 [2] 54 64 [2] 56 65 [2] 4d 63 [2] 51 64 [2] 4d 4b }

  condition:
    any of them
}