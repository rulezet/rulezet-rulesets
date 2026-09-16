rule TTP_XOR_QUAD_CurrentVersionRun_e622 {
  strings:
    $key_e622 = { b5 4d [2] 91 43 [2] ba 6f [2] 94 4d [2] 80 56 [2] 8f 4c [2] 91 51 [2] 93 50 [2] 88 56 [2] 94 51 [2] 88 7e }

  condition:
    any of them
}