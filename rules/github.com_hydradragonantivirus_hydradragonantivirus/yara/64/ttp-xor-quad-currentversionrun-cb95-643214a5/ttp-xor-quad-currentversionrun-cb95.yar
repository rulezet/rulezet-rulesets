rule TTP_XOR_QUAD_CurrentVersionRun_cb95 {
  strings:
    $key_cb95 = { 98 fa [2] bc f4 [2] 97 d8 [2] b9 fa [2] ad e1 [2] a2 fb [2] bc e6 [2] be e7 [2] a5 e1 [2] b9 e6 [2] a5 c9 }

  condition:
    any of them
}