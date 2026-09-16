rule TTP_XOR_QUAD_CurrentVersionRun_cbdc {
  strings:
    $key_cbdc = { 98 b3 [2] bc bd [2] 97 91 [2] b9 b3 [2] ad a8 [2] a2 b2 [2] bc af [2] be ae [2] a5 a8 [2] b9 af [2] a5 80 }

  condition:
    any of them
}