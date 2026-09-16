rule TTP_XOR_QUAD_CurrentVersionRun_fa30 {
  strings:
    $key_fa30 = { a9 5f [2] 8d 51 [2] a6 7d [2] 88 5f [2] 9c 44 [2] 93 5e [2] 8d 43 [2] 8f 42 [2] 94 44 [2] 88 43 [2] 94 6c }

  condition:
    any of them
}