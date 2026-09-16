rule TTP_XOR_QUAD_CurrentVersionRun_37f9 {
  strings:
    $key_37f9 = { 64 96 [2] 40 98 [2] 6b b4 [2] 45 96 [2] 51 8d [2] 5e 97 [2] 40 8a [2] 42 8b [2] 59 8d [2] 45 8a [2] 59 a5 }

  condition:
    any of them
}