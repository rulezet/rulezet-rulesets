rule TTP_XOR_QUAD_CurrentVersionRun_3488 {
  strings:
    $key_3488 = { 67 e7 [2] 43 e9 [2] 68 c5 [2] 46 e7 [2] 52 fc [2] 5d e6 [2] 43 fb [2] 41 fa [2] 5a fc [2] 46 fb [2] 5a d4 }

  condition:
    any of them
}