rule TTP_XOR_QUAD_CurrentVersionRun_cb88 {
  strings:
    $key_cb88 = { 98 e7 [2] bc e9 [2] 97 c5 [2] b9 e7 [2] ad fc [2] a2 e6 [2] bc fb [2] be fa [2] a5 fc [2] b9 fb [2] a5 d4 }

  condition:
    any of them
}