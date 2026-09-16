rule TTP_XOR_QUAD_CurrentVersionRun_dc8c {
  strings:
    $key_dc8c = { 8f e3 [2] ab ed [2] 80 c1 [2] ae e3 [2] ba f8 [2] b5 e2 [2] ab ff [2] a9 fe [2] b2 f8 [2] ae ff [2] b2 d0 }

  condition:
    any of them
}