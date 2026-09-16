rule TTP_XOR_QUAD_CurrentVersionRun_e612 {
  strings:
    $key_e612 = { b5 7d [2] 91 73 [2] ba 5f [2] 94 7d [2] 80 66 [2] 8f 7c [2] 91 61 [2] 93 60 [2] 88 66 [2] 94 61 [2] 88 4e }

  condition:
    any of them
}