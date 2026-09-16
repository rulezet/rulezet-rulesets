rule TTP_XOR_QUAD_CurrentVersionRun_3cfb {
  strings:
    $key_3cfb = { 6f 94 [2] 4b 9a [2] 60 b6 [2] 4e 94 [2] 5a 8f [2] 55 95 [2] 4b 88 [2] 49 89 [2] 52 8f [2] 4e 88 [2] 52 a7 }

  condition:
    any of them
}