rule TTP_XOR_QUAD_CurrentVersionRun_1be5 {
  strings:
    $key_1be5 = { 48 8a [2] 6c 84 [2] 47 a8 [2] 69 8a [2] 7d 91 [2] 72 8b [2] 6c 96 [2] 6e 97 [2] 75 91 [2] 69 96 [2] 75 b9 }

  condition:
    any of them
}