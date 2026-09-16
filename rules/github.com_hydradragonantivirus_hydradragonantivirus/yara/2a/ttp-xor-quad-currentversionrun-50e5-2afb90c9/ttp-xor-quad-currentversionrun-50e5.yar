rule TTP_XOR_QUAD_CurrentVersionRun_50e5 {
  strings:
    $key_50e5 = { 03 8a [2] 27 84 [2] 0c a8 [2] 22 8a [2] 36 91 [2] 39 8b [2] 27 96 [2] 25 97 [2] 3e 91 [2] 22 96 [2] 3e b9 }

  condition:
    any of them
}