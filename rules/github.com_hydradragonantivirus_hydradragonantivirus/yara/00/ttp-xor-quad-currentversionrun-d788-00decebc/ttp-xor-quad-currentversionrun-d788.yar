rule TTP_XOR_QUAD_CurrentVersionRun_d788 {
  strings:
    $key_d788 = { 84 e7 [2] a0 e9 [2] 8b c5 [2] a5 e7 [2] b1 fc [2] be e6 [2] a0 fb [2] a2 fa [2] b9 fc [2] a5 fb [2] b9 d4 }

  condition:
    any of them
}