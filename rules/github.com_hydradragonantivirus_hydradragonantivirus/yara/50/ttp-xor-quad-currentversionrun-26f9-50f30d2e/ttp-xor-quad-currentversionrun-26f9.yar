rule TTP_XOR_QUAD_CurrentVersionRun_26f9 {
  strings:
    $key_26f9 = { 75 96 [2] 51 98 [2] 7a b4 [2] 54 96 [2] 40 8d [2] 4f 97 [2] 51 8a [2] 53 8b [2] 48 8d [2] 54 8a [2] 48 a5 }

  condition:
    any of them
}