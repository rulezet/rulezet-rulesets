rule TTP_XOR_QUAD_CurrentVersionRun_351b {
  strings:
    $key_351b = { 66 74 [2] 42 7a [2] 69 56 [2] 47 74 [2] 53 6f [2] 5c 75 [2] 42 68 [2] 40 69 [2] 5b 6f [2] 47 68 [2] 5b 47 }

  condition:
    any of them
}