rule TTP_XOR_QUAD_CurrentVersionRun_616a {
  strings:
    $key_616a = { 32 05 [2] 16 0b [2] 3d 27 [2] 13 05 [2] 07 1e [2] 08 04 [2] 16 19 [2] 14 18 [2] 0f 1e [2] 13 19 [2] 0f 36 }

  condition:
    any of them
}