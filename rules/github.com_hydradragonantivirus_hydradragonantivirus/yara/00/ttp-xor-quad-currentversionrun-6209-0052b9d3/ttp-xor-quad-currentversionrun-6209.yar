rule TTP_XOR_QUAD_CurrentVersionRun_6209 {
  strings:
    $key_6209 = { 31 66 [2] 15 68 [2] 3e 44 [2] 10 66 [2] 04 7d [2] 0b 67 [2] 15 7a [2] 17 7b [2] 0c 7d [2] 10 7a [2] 0c 55 }

  condition:
    any of them
}