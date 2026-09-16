rule TTP_XOR_QUAD_CurrentVersionRun_05f9 {
  strings:
    $key_05f9 = { 56 96 [2] 72 98 [2] 59 b4 [2] 77 96 [2] 63 8d [2] 6c 97 [2] 72 8a [2] 70 8b [2] 6b 8d [2] 77 8a [2] 6b a5 }

  condition:
    any of them
}