rule TTP_XOR_QUAD_CurrentVersionRun_cb97 {
  strings:
    $key_cb97 = { 98 f8 [2] bc f6 [2] 97 da [2] b9 f8 [2] ad e3 [2] a2 f9 [2] bc e4 [2] be e5 [2] a5 e3 [2] b9 e4 [2] a5 cb }

  condition:
    any of them
}