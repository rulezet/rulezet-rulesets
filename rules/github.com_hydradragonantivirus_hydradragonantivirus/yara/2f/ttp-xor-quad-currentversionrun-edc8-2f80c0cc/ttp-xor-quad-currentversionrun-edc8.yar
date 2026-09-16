rule TTP_XOR_QUAD_CurrentVersionRun_edc8 {
  strings:
    $key_edc8 = { be a7 [2] 9a a9 [2] b1 85 [2] 9f a7 [2] 8b bc [2] 84 a6 [2] 9a bb [2] 98 ba [2] 83 bc [2] 9f bb [2] 83 94 }

  condition:
    any of them
}