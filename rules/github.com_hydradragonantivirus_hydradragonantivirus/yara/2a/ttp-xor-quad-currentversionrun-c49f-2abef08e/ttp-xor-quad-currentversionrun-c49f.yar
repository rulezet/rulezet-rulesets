rule TTP_XOR_QUAD_CurrentVersionRun_c49f {
  strings:
    $key_c49f = { 97 f0 [2] b3 fe [2] 98 d2 [2] b6 f0 [2] a2 eb [2] ad f1 [2] b3 ec [2] b1 ed [2] aa eb [2] b6 ec [2] aa c3 }

  condition:
    any of them
}