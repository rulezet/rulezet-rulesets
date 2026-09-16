rule TTP_XOR_QUAD_CurrentVersionRun_fa06 {
  strings:
    $key_fa06 = { a9 69 [2] 8d 67 [2] a6 4b [2] 88 69 [2] 9c 72 [2] 93 68 [2] 8d 75 [2] 8f 74 [2] 94 72 [2] 88 75 [2] 94 5a }

  condition:
    any of them
}