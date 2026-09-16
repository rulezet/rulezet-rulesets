rule TTP_XOR_QUAD_CurrentVersionRun_e617 {
  strings:
    $key_e617 = { b5 78 [2] 91 76 [2] ba 5a [2] 94 78 [2] 80 63 [2] 8f 79 [2] 91 64 [2] 93 65 [2] 88 63 [2] 94 64 [2] 88 4b }

  condition:
    any of them
}