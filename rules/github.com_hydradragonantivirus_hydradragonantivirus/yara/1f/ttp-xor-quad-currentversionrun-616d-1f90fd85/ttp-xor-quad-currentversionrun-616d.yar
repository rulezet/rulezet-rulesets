rule TTP_XOR_QUAD_CurrentVersionRun_616d {
  strings:
    $key_616d = { 32 02 [2] 16 0c [2] 3d 20 [2] 13 02 [2] 07 19 [2] 08 03 [2] 16 1e [2] 14 1f [2] 0f 19 [2] 13 1e [2] 0f 31 }

  condition:
    any of them
}