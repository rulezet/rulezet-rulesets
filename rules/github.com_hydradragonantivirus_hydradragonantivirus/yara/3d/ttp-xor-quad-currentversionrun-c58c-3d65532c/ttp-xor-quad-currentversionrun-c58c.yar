rule TTP_XOR_QUAD_CurrentVersionRun_c58c {
  strings:
    $key_c58c = { 96 e3 [2] b2 ed [2] 99 c1 [2] b7 e3 [2] a3 f8 [2] ac e2 [2] b2 ff [2] b0 fe [2] ab f8 [2] b7 ff [2] ab d0 }

  condition:
    any of them
}