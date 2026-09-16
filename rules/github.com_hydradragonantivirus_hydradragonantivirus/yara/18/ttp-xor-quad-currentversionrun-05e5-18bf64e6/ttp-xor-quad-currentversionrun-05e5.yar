rule TTP_XOR_QUAD_CurrentVersionRun_05e5 {
  strings:
    $key_05e5 = { 56 8a [2] 72 84 [2] 59 a8 [2] 77 8a [2] 63 91 [2] 6c 8b [2] 72 96 [2] 70 97 [2] 6b 91 [2] 77 96 [2] 6b b9 }

  condition:
    any of them
}