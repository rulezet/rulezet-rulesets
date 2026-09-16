rule TTP_XOR_QUAD_CurrentVersionRun_2afb {
  strings:
    $key_2afb = { 79 94 [2] 5d 9a [2] 76 b6 [2] 58 94 [2] 4c 8f [2] 43 95 [2] 5d 88 [2] 5f 89 [2] 44 8f [2] 58 88 [2] 44 a7 }

  condition:
    any of them
}