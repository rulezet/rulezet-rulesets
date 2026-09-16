rule TTP_XOR_QUAD_CurrentVersionRun_e624 {
  strings:
    $key_e624 = { b5 4b [2] 91 45 [2] ba 69 [2] 94 4b [2] 80 50 [2] 8f 4a [2] 91 57 [2] 93 56 [2] 88 50 [2] 94 57 [2] 88 78 }

  condition:
    any of them
}