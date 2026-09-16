rule TTP_XOR_QUAD_CurrentVersionRun_cb94 {
  strings:
    $key_cb94 = { 98 fb [2] bc f5 [2] 97 d9 [2] b9 fb [2] ad e0 [2] a2 fa [2] bc e7 [2] be e6 [2] a5 e0 [2] b9 e7 [2] a5 c8 }

  condition:
    any of them
}