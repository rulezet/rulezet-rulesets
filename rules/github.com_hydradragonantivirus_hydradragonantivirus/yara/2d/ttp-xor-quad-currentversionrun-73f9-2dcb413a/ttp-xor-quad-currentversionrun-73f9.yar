rule TTP_XOR_QUAD_CurrentVersionRun_73f9 {
  strings:
    $key_73f9 = { 20 96 [2] 04 98 [2] 2f b4 [2] 01 96 [2] 15 8d [2] 1a 97 [2] 04 8a [2] 06 8b [2] 1d 8d [2] 01 8a [2] 1d a5 }

  condition:
    any of them
}