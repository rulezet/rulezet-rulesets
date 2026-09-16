rule TTP_XOR_QUAD_CurrentVersionRun_ef49 {
  strings:
    $key_ef49 = { bc 26 [2] 98 28 [2] b3 04 [2] 9d 26 [2] 89 3d [2] 86 27 [2] 98 3a [2] 9a 3b [2] 81 3d [2] 9d 3a [2] 81 15 }

  condition:
    any of them
}