rule TTP_XOR_QUAD_CurrentVersionRun_dc9f {
  strings:
    $key_dc9f = { 8f f0 [2] ab fe [2] 80 d2 [2] ae f0 [2] ba eb [2] b5 f1 [2] ab ec [2] a9 ed [2] b2 eb [2] ae ec [2] b2 c3 }

  condition:
    any of them
}