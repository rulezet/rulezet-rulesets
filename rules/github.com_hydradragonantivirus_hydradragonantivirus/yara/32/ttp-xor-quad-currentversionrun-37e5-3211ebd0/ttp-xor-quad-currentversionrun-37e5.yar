rule TTP_XOR_QUAD_CurrentVersionRun_37e5 {
  strings:
    $key_37e5 = { 64 8a [2] 40 84 [2] 6b a8 [2] 45 8a [2] 51 91 [2] 5e 8b [2] 40 96 [2] 42 97 [2] 59 91 [2] 45 96 [2] 59 b9 }

  condition:
    any of them
}