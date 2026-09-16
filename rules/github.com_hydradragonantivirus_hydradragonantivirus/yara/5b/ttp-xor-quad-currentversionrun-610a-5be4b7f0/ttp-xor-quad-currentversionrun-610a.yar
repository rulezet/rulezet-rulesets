rule TTP_XOR_QUAD_CurrentVersionRun_610a {
  strings:
    $key_610a = { 32 65 [2] 16 6b [2] 3d 47 [2] 13 65 [2] 07 7e [2] 08 64 [2] 16 79 [2] 14 78 [2] 0f 7e [2] 13 79 [2] 0f 56 }

  condition:
    any of them
}