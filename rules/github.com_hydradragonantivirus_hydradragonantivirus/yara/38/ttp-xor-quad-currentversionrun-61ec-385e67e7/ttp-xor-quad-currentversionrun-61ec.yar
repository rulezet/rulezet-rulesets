rule TTP_XOR_QUAD_CurrentVersionRun_61ec {
  strings:
    $key_61ec = { 32 83 [2] 16 8d [2] 3d a1 [2] 13 83 [2] 07 98 [2] 08 82 [2] 16 9f [2] 14 9e [2] 0f 98 [2] 13 9f [2] 0f b0 }

  condition:
    any of them
}