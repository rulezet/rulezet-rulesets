rule TTP_XOR_QUAD_CurrentVersionRun_cbfe {
  strings:
    $key_cbfe = { 98 91 [2] bc 9f [2] 97 b3 [2] b9 91 [2] ad 8a [2] a2 90 [2] bc 8d [2] be 8c [2] a5 8a [2] b9 8d [2] a5 a2 }

  condition:
    any of them
}