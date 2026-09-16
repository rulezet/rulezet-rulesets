rule TTP_XOR_QUAD_CurrentVersionRun_3be4 {
  strings:
    $key_3be4 = { 68 8b [2] 4c 85 [2] 67 a9 [2] 49 8b [2] 5d 90 [2] 52 8a [2] 4c 97 [2] 4e 96 [2] 55 90 [2] 49 97 [2] 55 b8 }

  condition:
    any of them
}