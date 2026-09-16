rule TTP_XOR_QUAD_CurrentVersionRun_74fe {
  strings:
    $key_74fe = { 27 91 [2] 03 9f [2] 28 b3 [2] 06 91 [2] 12 8a [2] 1d 90 [2] 03 8d [2] 01 8c [2] 1a 8a [2] 06 8d [2] 1a a2 }

  condition:
    any of them
}