rule TTP_XOR_QUAD_CurrentVersionRun_d79d {
  strings:
    $key_d79d = { 84 f2 [2] a0 fc [2] 8b d0 [2] a5 f2 [2] b1 e9 [2] be f3 [2] a0 ee [2] a2 ef [2] b9 e9 [2] a5 ee [2] b9 c1 }

  condition:
    any of them
}