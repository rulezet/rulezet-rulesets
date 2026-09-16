rule TTP_XOR_QUAD_CurrentVersionRun_8db9 {
  strings:
    $key_8db9 = { de d6 [2] fa d8 [2] d1 f4 [2] ff d6 [2] eb cd [2] e4 d7 [2] fa ca [2] f8 cb [2] e3 cd [2] ff ca [2] e3 e5 }

  condition:
    any of them
}