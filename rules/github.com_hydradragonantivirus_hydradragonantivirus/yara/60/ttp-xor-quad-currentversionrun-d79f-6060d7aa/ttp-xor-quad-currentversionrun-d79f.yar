rule TTP_XOR_QUAD_CurrentVersionRun_d79f {
  strings:
    $key_d79f = { 84 f0 [2] a0 fe [2] 8b d2 [2] a5 f0 [2] b1 eb [2] be f1 [2] a0 ec [2] a2 ed [2] b9 eb [2] a5 ec [2] b9 c3 }

  condition:
    any of them
}