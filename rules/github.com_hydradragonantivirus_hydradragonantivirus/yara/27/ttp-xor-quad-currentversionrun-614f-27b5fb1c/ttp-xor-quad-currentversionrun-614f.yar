rule TTP_XOR_QUAD_CurrentVersionRun_614f {
  strings:
    $key_614f = { 32 20 [2] 16 2e [2] 3d 02 [2] 13 20 [2] 07 3b [2] 08 21 [2] 16 3c [2] 14 3d [2] 0f 3b [2] 13 3c [2] 0f 13 }

  condition:
    any of them
}