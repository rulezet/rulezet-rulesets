rule TTP_XOR_QUAD_CurrentVersionRun_61c1 {
  strings:
    $key_61c1 = { 32 ae [2] 16 a0 [2] 3d 8c [2] 13 ae [2] 07 b5 [2] 08 af [2] 16 b2 [2] 14 b3 [2] 0f b5 [2] 13 b2 [2] 0f 9d }

  condition:
    any of them
}