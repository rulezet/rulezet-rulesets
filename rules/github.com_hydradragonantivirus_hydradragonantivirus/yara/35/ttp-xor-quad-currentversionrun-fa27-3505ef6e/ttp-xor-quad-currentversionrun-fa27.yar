rule TTP_XOR_QUAD_CurrentVersionRun_fa27 {
  strings:
    $key_fa27 = { a9 48 [2] 8d 46 [2] a6 6a [2] 88 48 [2] 9c 53 [2] 93 49 [2] 8d 54 [2] 8f 55 [2] 94 53 [2] 88 54 [2] 94 7b }

  condition:
    any of them
}