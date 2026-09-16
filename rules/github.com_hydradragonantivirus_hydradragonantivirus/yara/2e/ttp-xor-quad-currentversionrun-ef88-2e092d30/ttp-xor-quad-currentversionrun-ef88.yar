rule TTP_XOR_QUAD_CurrentVersionRun_ef88 {
  strings:
    $key_ef88 = { bc e7 [2] 98 e9 [2] b3 c5 [2] 9d e7 [2] 89 fc [2] 86 e6 [2] 98 fb [2] 9a fa [2] 81 fc [2] 9d fb [2] 81 d4 }

  condition:
    any of them
}