rule TTP_XOR_QUAD_CurrentVersionRun_3bf9 {
  strings:
    $key_3bf9 = { 68 96 [2] 4c 98 [2] 67 b4 [2] 49 96 [2] 5d 8d [2] 52 97 [2] 4c 8a [2] 4e 8b [2] 55 8d [2] 49 8a [2] 55 a5 }

  condition:
    any of them
}