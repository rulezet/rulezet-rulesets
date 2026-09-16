rule TTP_XOR_QUAD_CurrentVersionRun_e66b {
  strings:
    $key_e66b = { b5 04 [2] 91 0a [2] ba 26 [2] 94 04 [2] 80 1f [2] 8f 05 [2] 91 18 [2] 93 19 [2] 88 1f [2] 94 18 [2] 88 37 }

  condition:
    any of them
}