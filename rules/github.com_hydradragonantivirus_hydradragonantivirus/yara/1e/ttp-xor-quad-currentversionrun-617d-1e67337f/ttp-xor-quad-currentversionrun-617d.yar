rule TTP_XOR_QUAD_CurrentVersionRun_617d {
  strings:
    $key_617d = { 32 12 [2] 16 1c [2] 3d 30 [2] 13 12 [2] 07 09 [2] 08 13 [2] 16 0e [2] 14 0f [2] 0f 09 [2] 13 0e [2] 0f 21 }

  condition:
    any of them
}