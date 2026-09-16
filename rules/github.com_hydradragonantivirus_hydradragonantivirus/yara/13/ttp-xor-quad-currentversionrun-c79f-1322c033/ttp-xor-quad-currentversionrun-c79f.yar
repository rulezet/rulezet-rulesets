rule TTP_XOR_QUAD_CurrentVersionRun_c79f {
  strings:
    $key_c79f = { 94 f0 [2] b0 fe [2] 9b d2 [2] b5 f0 [2] a1 eb [2] ae f1 [2] b0 ec [2] b2 ed [2] a9 eb [2] b5 ec [2] a9 c3 }

  condition:
    any of them
}