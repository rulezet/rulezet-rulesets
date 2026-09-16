rule TTP_XOR_QUAD_CurrentVersionRun_e4f7 {
  strings:
    $key_e4f7 = { b7 98 [2] 93 96 [2] b8 ba [2] 96 98 [2] 82 83 [2] 8d 99 [2] 93 84 [2] 91 85 [2] 8a 83 [2] 96 84 [2] 8a ab }

  condition:
    any of them
}