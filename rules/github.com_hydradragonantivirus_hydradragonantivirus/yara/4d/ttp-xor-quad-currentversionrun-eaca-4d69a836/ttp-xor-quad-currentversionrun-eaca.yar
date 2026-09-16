rule TTP_XOR_QUAD_CurrentVersionRun_eaca {
  strings:
    $key_eaca = { b9 a5 [2] 9d ab [2] b6 87 [2] 98 a5 [2] 8c be [2] 83 a4 [2] 9d b9 [2] 9f b8 [2] 84 be [2] 98 b9 [2] 84 96 }

  condition:
    any of them
}