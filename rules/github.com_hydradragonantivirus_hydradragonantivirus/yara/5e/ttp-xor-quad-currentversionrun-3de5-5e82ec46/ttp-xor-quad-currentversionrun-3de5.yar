rule TTP_XOR_QUAD_CurrentVersionRun_3de5 {
  strings:
    $key_3de5 = { 6e 8a [2] 4a 84 [2] 61 a8 [2] 4f 8a [2] 5b 91 [2] 54 8b [2] 4a 96 [2] 48 97 [2] 53 91 [2] 4f 96 [2] 53 b9 }

  condition:
    any of them
}