rule TTP_XOR_QUAD_CurrentVersionRun_cb8a {
  strings:
    $key_cb8a = { 98 e5 [2] bc eb [2] 97 c7 [2] b9 e5 [2] ad fe [2] a2 e4 [2] bc f9 [2] be f8 [2] a5 fe [2] b9 f9 [2] a5 d6 }

  condition:
    any of them
}