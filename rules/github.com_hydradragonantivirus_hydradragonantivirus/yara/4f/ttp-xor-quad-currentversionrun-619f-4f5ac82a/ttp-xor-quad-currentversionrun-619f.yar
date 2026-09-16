rule TTP_XOR_QUAD_CurrentVersionRun_619f {
  strings:
    $key_619f = { 32 f0 [2] 16 fe [2] 3d d2 [2] 13 f0 [2] 07 eb [2] 08 f1 [2] 16 ec [2] 14 ed [2] 0f eb [2] 13 ec [2] 0f c3 }

  condition:
    any of them
}