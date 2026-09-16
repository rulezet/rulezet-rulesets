rule TTP_XOR_QUAD_CurrentVersionRun_3cf9 {
  strings:
    $key_3cf9 = { 6f 96 [2] 4b 98 [2] 60 b4 [2] 4e 96 [2] 5a 8d [2] 55 97 [2] 4b 8a [2] 49 8b [2] 52 8d [2] 4e 8a [2] 52 a5 }

  condition:
    any of them
}