rule TTP_XOR_QUAD_CurrentVersionRun_e4eb {
  strings:
    $key_e4eb = { b7 84 [2] 93 8a [2] b8 a6 [2] 96 84 [2] 82 9f [2] 8d 85 [2] 93 98 [2] 91 99 [2] 8a 9f [2] 96 98 [2] 8a b7 }

  condition:
    any of them
}