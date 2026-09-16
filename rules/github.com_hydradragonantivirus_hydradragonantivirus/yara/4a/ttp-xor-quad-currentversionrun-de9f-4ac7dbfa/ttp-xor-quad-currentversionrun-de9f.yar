rule TTP_XOR_QUAD_CurrentVersionRun_de9f {
  strings:
    $key_de9f = { 8d f0 [2] a9 fe [2] 82 d2 [2] ac f0 [2] b8 eb [2] b7 f1 [2] a9 ec [2] ab ed [2] b0 eb [2] ac ec [2] b0 c3 }

  condition:
    any of them
}