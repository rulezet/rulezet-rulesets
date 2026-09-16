rule TTP_XOR_QUAD_CurrentVersionRun_e63e {
  strings:
    $key_e63e = { b5 51 [2] 91 5f [2] ba 73 [2] 94 51 [2] 80 4a [2] 8f 50 [2] 91 4d [2] 93 4c [2] 88 4a [2] 94 4d [2] 88 62 }

  condition:
    any of them
}