rule TTP_XOR_QUAD_CurrentVersionRun_09e5 {
  strings:
    $key_09e5 = { 5a 8a [2] 7e 84 [2] 55 a8 [2] 7b 8a [2] 6f 91 [2] 60 8b [2] 7e 96 [2] 7c 97 [2] 67 91 [2] 7b 96 [2] 67 b9 }

  condition:
    any of them
}