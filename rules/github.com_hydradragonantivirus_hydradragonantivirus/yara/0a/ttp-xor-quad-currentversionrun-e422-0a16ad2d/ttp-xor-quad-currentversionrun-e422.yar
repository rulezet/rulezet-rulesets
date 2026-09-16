rule TTP_XOR_QUAD_CurrentVersionRun_e422 {
  strings:
    $key_e422 = { b7 4d [2] 93 43 [2] b8 6f [2] 96 4d [2] 82 56 [2] 8d 4c [2] 93 51 [2] 91 50 [2] 8a 56 [2] 96 51 [2] 8a 7e }

  condition:
    any of them
}