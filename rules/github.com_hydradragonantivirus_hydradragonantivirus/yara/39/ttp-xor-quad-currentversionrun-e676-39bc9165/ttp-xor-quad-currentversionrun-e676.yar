rule TTP_XOR_QUAD_CurrentVersionRun_e676 {
  strings:
    $key_e676 = { b5 19 [2] 91 17 [2] ba 3b [2] 94 19 [2] 80 02 [2] 8f 18 [2] 91 05 [2] 93 04 [2] 88 02 [2] 94 05 [2] 88 2a }

  condition:
    any of them
}