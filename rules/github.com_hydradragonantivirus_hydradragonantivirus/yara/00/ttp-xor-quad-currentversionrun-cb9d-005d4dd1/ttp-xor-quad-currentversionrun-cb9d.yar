rule TTP_XOR_QUAD_CurrentVersionRun_cb9d {
  strings:
    $key_cb9d = { 98 f2 [2] bc fc [2] 97 d0 [2] b9 f2 [2] ad e9 [2] a2 f3 [2] bc ee [2] be ef [2] a5 e9 [2] b9 ee [2] a5 c1 }

  condition:
    any of them
}