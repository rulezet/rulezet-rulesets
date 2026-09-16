rule TTP_XOR_QUAD_CurrentVersionRun_f788 {
  strings:
    $key_f788 = { a4 e7 [2] 80 e9 [2] ab c5 [2] 85 e7 [2] 91 fc [2] 9e e6 [2] 80 fb [2] 82 fa [2] 99 fc [2] 85 fb [2] 99 d4 }

  condition:
    any of them
}