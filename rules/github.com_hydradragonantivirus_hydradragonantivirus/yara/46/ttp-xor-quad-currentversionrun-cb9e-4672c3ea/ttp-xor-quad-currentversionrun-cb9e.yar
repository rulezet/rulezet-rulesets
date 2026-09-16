rule TTP_XOR_QUAD_CurrentVersionRun_cb9e {
  strings:
    $key_cb9e = { 98 f1 [2] bc ff [2] 97 d3 [2] b9 f1 [2] ad ea [2] a2 f0 [2] bc ed [2] be ec [2] a5 ea [2] b9 ed [2] a5 c2 }

  condition:
    any of them
}