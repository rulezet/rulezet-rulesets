rule TTP_XOR_QUAD_CurrentVersionRun_fae1 {
  strings:
    $key_fae1 = { a9 8e [2] 8d 80 [2] a6 ac [2] 88 8e [2] 9c 95 [2] 93 8f [2] 8d 92 [2] 8f 93 [2] 94 95 [2] 88 92 [2] 94 bd }

  condition:
    any of them
}