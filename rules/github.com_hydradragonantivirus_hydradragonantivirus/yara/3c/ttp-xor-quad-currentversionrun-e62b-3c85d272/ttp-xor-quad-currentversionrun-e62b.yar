rule TTP_XOR_QUAD_CurrentVersionRun_e62b {
  strings:
    $key_e62b = { b5 44 [2] 91 4a [2] ba 66 [2] 94 44 [2] 80 5f [2] 8f 45 [2] 91 58 [2] 93 59 [2] 88 5f [2] 94 58 [2] 88 77 }

  condition:
    any of them
}