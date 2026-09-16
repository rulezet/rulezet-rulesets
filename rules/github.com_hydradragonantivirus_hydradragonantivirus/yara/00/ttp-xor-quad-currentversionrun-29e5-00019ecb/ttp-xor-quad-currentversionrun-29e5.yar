rule TTP_XOR_QUAD_CurrentVersionRun_29e5 {
  strings:
    $key_29e5 = { 7a 8a [2] 5e 84 [2] 75 a8 [2] 5b 8a [2] 4f 91 [2] 40 8b [2] 5e 96 [2] 5c 97 [2] 47 91 [2] 5b 96 [2] 47 b9 }

  condition:
    any of them
}