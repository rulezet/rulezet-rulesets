rule TTP_XOR_QUAD_CurrentVersionRun_2488 {
  strings:
    $key_2488 = { 77 e7 [2] 53 e9 [2] 78 c5 [2] 56 e7 [2] 42 fc [2] 4d e6 [2] 53 fb [2] 51 fa [2] 4a fc [2] 56 fb [2] 4a d4 }

  condition:
    any of them
}