rule TTP_XOR_QUAD_CurrentVersionRun_3b65 {
  strings:
    $key_3b65 = { 68 0a [2] 4c 04 [2] 67 28 [2] 49 0a [2] 5d 11 [2] 52 0b [2] 4c 16 [2] 4e 17 [2] 55 11 [2] 49 16 [2] 55 39 }

  condition:
    any of them
}