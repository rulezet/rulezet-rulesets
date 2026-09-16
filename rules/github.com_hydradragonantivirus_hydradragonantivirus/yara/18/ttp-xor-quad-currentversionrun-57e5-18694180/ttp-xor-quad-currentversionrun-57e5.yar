rule TTP_XOR_QUAD_CurrentVersionRun_57e5 {
  strings:
    $key_57e5 = { 04 8a [2] 20 84 [2] 0b a8 [2] 25 8a [2] 31 91 [2] 3e 8b [2] 20 96 [2] 22 97 [2] 39 91 [2] 25 96 [2] 39 b9 }

  condition:
    any of them
}