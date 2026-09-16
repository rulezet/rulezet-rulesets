rule TTP_XOR_QUAD_CurrentVersionRun_e67b {
  strings:
    $key_e67b = { b5 14 [2] 91 1a [2] ba 36 [2] 94 14 [2] 80 0f [2] 8f 15 [2] 91 08 [2] 93 09 [2] 88 0f [2] 94 08 [2] 88 27 }

  condition:
    any of them
}