rule TTP_XOR_QUAD_CurrentVersionRun_cb96 {
  strings:
    $key_cb96 = { 98 f9 [2] bc f7 [2] 97 db [2] b9 f9 [2] ad e2 [2] a2 f8 [2] bc e5 [2] be e4 [2] a5 e2 [2] b9 e5 [2] a5 ca }

  condition:
    any of them
}