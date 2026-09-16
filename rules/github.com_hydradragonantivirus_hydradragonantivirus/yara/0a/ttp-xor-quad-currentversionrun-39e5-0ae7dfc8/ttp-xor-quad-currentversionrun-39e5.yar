rule TTP_XOR_QUAD_CurrentVersionRun_39e5 {
  strings:
    $key_39e5 = { 6a 8a [2] 4e 84 [2] 65 a8 [2] 4b 8a [2] 5f 91 [2] 50 8b [2] 4e 96 [2] 4c 97 [2] 57 91 [2] 4b 96 [2] 57 b9 }

  condition:
    any of them
}