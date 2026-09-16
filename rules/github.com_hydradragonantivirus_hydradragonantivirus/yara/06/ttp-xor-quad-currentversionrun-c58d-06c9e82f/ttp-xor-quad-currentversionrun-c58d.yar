rule TTP_XOR_QUAD_CurrentVersionRun_c58d {
  strings:
    $key_c58d = { 96 e2 [2] b2 ec [2] 99 c0 [2] b7 e2 [2] a3 f9 [2] ac e3 [2] b2 fe [2] b0 ff [2] ab f9 [2] b7 fe [2] ab d1 }

  condition:
    any of them
}