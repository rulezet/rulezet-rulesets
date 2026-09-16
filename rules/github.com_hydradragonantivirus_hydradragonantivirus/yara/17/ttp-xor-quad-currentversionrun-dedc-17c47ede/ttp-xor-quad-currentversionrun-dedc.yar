rule TTP_XOR_QUAD_CurrentVersionRun_dedc {
  strings:
    $key_dedc = { 8d b3 [2] a9 bd [2] 82 91 [2] ac b3 [2] b8 a8 [2] b7 b2 [2] a9 af [2] ab ae [2] b0 a8 [2] ac af [2] b0 80 }

  condition:
    any of them
}