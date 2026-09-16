rule TTP_XOR_QUAD_CurrentVersionRun_faec {
  strings:
    $key_faec = { a9 83 [2] 8d 8d [2] a6 a1 [2] 88 83 [2] 9c 98 [2] 93 82 [2] 8d 9f [2] 8f 9e [2] 94 98 [2] 88 9f [2] 94 b0 }

  condition:
    any of them
}