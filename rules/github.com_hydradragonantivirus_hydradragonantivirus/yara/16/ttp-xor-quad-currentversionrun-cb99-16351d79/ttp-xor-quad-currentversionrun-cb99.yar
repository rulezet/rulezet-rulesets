rule TTP_XOR_QUAD_CurrentVersionRun_cb99 {
  strings:
    $key_cb99 = { 98 f6 [2] bc f8 [2] 97 d4 [2] b9 f6 [2] ad ed [2] a2 f7 [2] bc ea [2] be eb [2] a5 ed [2] b9 ea [2] a5 c5 }

  condition:
    any of them
}