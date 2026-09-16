rule TTP_XOR_QUAD_CurrentVersionRun_e60c {
  strings:
    $key_e60c = { b5 63 [2] 91 6d [2] ba 41 [2] 94 63 [2] 80 78 [2] 8f 62 [2] 91 7f [2] 93 7e [2] 88 78 [2] 94 7f [2] 88 50 }

  condition:
    any of them
}