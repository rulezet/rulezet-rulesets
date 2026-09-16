rule TTP_XOR_QUAD_CurrentVersionRun_50f9 {
  strings:
    $key_50f9 = { 03 96 [2] 27 98 [2] 0c b4 [2] 22 96 [2] 36 8d [2] 39 97 [2] 27 8a [2] 25 8b [2] 3e 8d [2] 22 8a [2] 3e a5 }

  condition:
    any of them
}