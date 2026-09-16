rule TTP_XOR_QUAD_CurrentVersionRun_cb80 {
  strings:
    $key_cb80 = { 98 ef [2] bc e1 [2] 97 cd [2] b9 ef [2] ad f4 [2] a2 ee [2] bc f3 [2] be f2 [2] a5 f4 [2] b9 f3 [2] a5 dc }

  condition:
    any of them
}