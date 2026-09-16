rule TTP_XOR_QUAD_CurrentVersionRun_9a9d {
  strings:
    $key_9a9d = { c9 f2 [2] ed fc [2] c6 d0 [2] e8 f2 [2] fc e9 [2] f3 f3 [2] ed ee [2] ef ef [2] f4 e9 [2] e8 ee [2] f4 c1 }

  condition:
    any of them
}