rule TTP_XOR_QUAD_CurrentVersionRun_19f8 {
  strings:
    $key_19f8 = { 4a 97 [2] 6e 99 [2] 45 b5 [2] 6b 97 [2] 7f 8c [2] 70 96 [2] 6e 8b [2] 6c 8a [2] 77 8c [2] 6b 8b [2] 77 a4 }

  condition:
    any of them
}