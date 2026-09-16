rule TTP_XOR_QUAD_CurrentVersionRun_6131 {
  strings:
    $key_6131 = { 32 5e [2] 16 50 [2] 3d 7c [2] 13 5e [2] 07 45 [2] 08 5f [2] 16 42 [2] 14 43 [2] 0f 45 [2] 13 42 [2] 0f 6d }

  condition:
    any of them
}