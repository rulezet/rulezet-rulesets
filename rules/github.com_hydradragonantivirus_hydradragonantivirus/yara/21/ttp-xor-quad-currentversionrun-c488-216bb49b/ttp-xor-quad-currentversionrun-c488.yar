rule TTP_XOR_QUAD_CurrentVersionRun_c488 {
  strings:
    $key_c488 = { 97 e7 [2] b3 e9 [2] 98 c5 [2] b6 e7 [2] a2 fc [2] ad e6 [2] b3 fb [2] b1 fa [2] aa fc [2] b6 fb [2] aa d4 }

  condition:
    any of them
}