rule TTP_XOR_QUAD_CurrentVersionRun_1609 {
  strings:
    $key_1609 = { 45 66 [2] 61 68 [2] 4a 44 [2] 64 66 [2] 70 7d [2] 7f 67 [2] 61 7a [2] 63 7b [2] 78 7d [2] 64 7a [2] 78 55 }

  condition:
    any of them
}