rule TTP_XOR_QUAD_CurrentVersionRun_e632 {
  strings:
    $key_e632 = { b5 5d [2] 91 53 [2] ba 7f [2] 94 5d [2] 80 46 [2] 8f 5c [2] 91 41 [2] 93 40 [2] 88 46 [2] 94 41 [2] 88 6e }

  condition:
    any of them
}