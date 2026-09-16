rule TTP_XOR_QUAD_CurrentVersionRun_e688 {
  strings:
    $key_e688 = { b5 e7 [2] 91 e9 [2] ba c5 [2] 94 e7 [2] 80 fc [2] 8f e6 [2] 91 fb [2] 93 fa [2] 88 fc [2] 94 fb [2] 88 d4 }

  condition:
    any of them
}