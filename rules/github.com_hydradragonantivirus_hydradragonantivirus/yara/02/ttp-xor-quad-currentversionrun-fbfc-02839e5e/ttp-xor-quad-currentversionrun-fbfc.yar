rule TTP_XOR_QUAD_CurrentVersionRun_fbfc {
  strings:
    $key_fbfc = { a8 93 [2] 8c 9d [2] a7 b1 [2] 89 93 [2] 9d 88 [2] 92 92 [2] 8c 8f [2] 8e 8e [2] 95 88 [2] 89 8f [2] 95 a0 }

  condition:
    any of them
}