rule TTP_XOR_QUAD_CurrentVersionRun_cb9c {
  strings:
    $key_cb9c = { 98 f3 [2] bc fd [2] 97 d1 [2] b9 f3 [2] ad e8 [2] a2 f2 [2] bc ef [2] be ee [2] a5 e8 [2] b9 ef [2] a5 c0 }

  condition:
    any of them
}