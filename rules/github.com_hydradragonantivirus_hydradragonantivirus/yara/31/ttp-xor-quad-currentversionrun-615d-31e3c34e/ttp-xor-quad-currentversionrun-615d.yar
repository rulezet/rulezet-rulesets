rule TTP_XOR_QUAD_CurrentVersionRun_615d {
  strings:
    $key_615d = { 32 32 [2] 16 3c [2] 3d 10 [2] 13 32 [2] 07 29 [2] 08 33 [2] 16 2e [2] 14 2f [2] 0f 29 [2] 13 2e [2] 0f 01 }

  condition:
    any of them
}