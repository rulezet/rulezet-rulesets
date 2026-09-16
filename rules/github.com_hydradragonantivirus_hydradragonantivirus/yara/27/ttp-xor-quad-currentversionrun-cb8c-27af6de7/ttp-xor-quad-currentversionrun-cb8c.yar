rule TTP_XOR_QUAD_CurrentVersionRun_cb8c {
  strings:
    $key_cb8c = { 98 e3 [2] bc ed [2] 97 c1 [2] b9 e3 [2] ad f8 [2] a2 e2 [2] bc ff [2] be fe [2] a5 f8 [2] b9 ff [2] a5 d0 }

  condition:
    any of them
}