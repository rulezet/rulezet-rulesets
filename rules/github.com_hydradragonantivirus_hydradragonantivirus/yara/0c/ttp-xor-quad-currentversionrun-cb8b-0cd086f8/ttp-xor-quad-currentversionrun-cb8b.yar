rule TTP_XOR_QUAD_CurrentVersionRun_cb8b {
  strings:
    $key_cb8b = { 98 e4 [2] bc ea [2] 97 c6 [2] b9 e4 [2] ad ff [2] a2 e5 [2] bc f8 [2] be f9 [2] a5 ff [2] b9 f8 [2] a5 d7 }

  condition:
    any of them
}