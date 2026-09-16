rule TTP_XOR_QUAD_CurrentVersionRun_617c {
  strings:
    $key_617c = { 32 13 [2] 16 1d [2] 3d 31 [2] 13 13 [2] 07 08 [2] 08 12 [2] 16 0f [2] 14 0e [2] 0f 08 [2] 13 0f [2] 0f 20 }

  condition:
    any of them
}