rule TTP_XOR_QUAD_CurrentVersionRun_e606 {
  strings:
    $key_e606 = { b5 69 [2] 91 67 [2] ba 4b [2] 94 69 [2] 80 72 [2] 8f 68 [2] 91 75 [2] 93 74 [2] 88 72 [2] 94 75 [2] 88 5a }

  condition:
    any of them
}