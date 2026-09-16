rule TTP_XOR_QUAD_CurrentVersionRun_dc9d {
  strings:
    $key_dc9d = { 8f f2 [2] ab fc [2] 80 d0 [2] ae f2 [2] ba e9 [2] b5 f3 [2] ab ee [2] a9 ef [2] b2 e9 [2] ae ee [2] b2 c1 }

  condition:
    any of them
}