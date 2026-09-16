rule TTP_XOR_QUAD_CurrentVersionRun_e63b {
  strings:
    $key_e63b = { b5 54 [2] 91 5a [2] ba 76 [2] 94 54 [2] 80 4f [2] 8f 55 [2] 91 48 [2] 93 49 [2] 88 4f [2] 94 48 [2] 88 67 }

  condition:
    any of them
}