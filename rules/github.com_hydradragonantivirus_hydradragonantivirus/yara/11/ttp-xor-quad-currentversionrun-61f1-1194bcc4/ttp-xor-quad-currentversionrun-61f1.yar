rule TTP_XOR_QUAD_CurrentVersionRun_61f1 {
  strings:
    $key_61f1 = { 32 9e [2] 16 90 [2] 3d bc [2] 13 9e [2] 07 85 [2] 08 9f [2] 16 82 [2] 14 83 [2] 0f 85 [2] 13 82 [2] 0f ad }

  condition:
    any of them
}