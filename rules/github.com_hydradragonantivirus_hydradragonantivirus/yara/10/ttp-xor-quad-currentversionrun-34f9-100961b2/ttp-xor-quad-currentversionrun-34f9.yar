rule TTP_XOR_QUAD_CurrentVersionRun_34f9 {
  strings:
    $key_34f9 = { 67 96 [2] 43 98 [2] 68 b4 [2] 46 96 [2] 52 8d [2] 5d 97 [2] 43 8a [2] 41 8b [2] 5a 8d [2] 46 8a [2] 5a a5 }

  condition:
    any of them
}