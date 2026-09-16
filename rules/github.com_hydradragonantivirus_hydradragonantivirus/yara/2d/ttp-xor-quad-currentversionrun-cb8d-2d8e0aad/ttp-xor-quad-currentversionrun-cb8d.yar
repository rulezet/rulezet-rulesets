rule TTP_XOR_QUAD_CurrentVersionRun_cb8d {
  strings:
    $key_cb8d = { 98 e2 [2] bc ec [2] 97 c0 [2] b9 e2 [2] ad f9 [2] a2 e3 [2] bc fe [2] be ff [2] a5 f9 [2] b9 fe [2] a5 d1 }

  condition:
    any of them
}