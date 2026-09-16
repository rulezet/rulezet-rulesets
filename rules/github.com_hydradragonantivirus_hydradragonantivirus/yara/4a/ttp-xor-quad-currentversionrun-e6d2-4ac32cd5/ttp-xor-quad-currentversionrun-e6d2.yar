rule TTP_XOR_QUAD_CurrentVersionRun_e6d2 {
  strings:
    $key_e6d2 = { b5 bd [2] 91 b3 [2] ba 9f [2] 94 bd [2] 80 a6 [2] 8f bc [2] 91 a1 [2] 93 a0 [2] 88 a6 [2] 94 a1 [2] 88 8e }

  condition:
    any of them
}