rule TTP_XOR_QUAD_CurrentVersionRun_fafa {
  strings:
    $key_fafa = { a9 95 [2] 8d 9b [2] a6 b7 [2] 88 95 [2] 9c 8e [2] 93 94 [2] 8d 89 [2] 8f 88 [2] 94 8e [2] 88 89 [2] 94 a6 }

  condition:
    any of them
}