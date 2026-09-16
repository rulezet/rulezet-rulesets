rule TTP_XOR_QUAD_CurrentVersionRun_29f9 {
  strings:
    $key_29f9 = { 7a 96 [2] 5e 98 [2] 75 b4 [2] 5b 96 [2] 4f 8d [2] 40 97 [2] 5e 8a [2] 5c 8b [2] 47 8d [2] 5b 8a [2] 47 a5 }

  condition:
    any of them
}