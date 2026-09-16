rule TTP_XOR_QUAD_CurrentVersionRun_e626 {
  strings:
    $key_e626 = { b5 49 [2] 91 47 [2] ba 6b [2] 94 49 [2] 80 52 [2] 8f 48 [2] 91 55 [2] 93 54 [2] 88 52 [2] 94 55 [2] 88 7a }

  condition:
    any of them
}