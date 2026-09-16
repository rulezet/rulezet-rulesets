rule TTP_XOR_QUAD_CurrentVersionRun_d749 {
  strings:
    $key_d749 = { 84 26 [2] a0 28 [2] 8b 04 [2] a5 26 [2] b1 3d [2] be 27 [2] a0 3a [2] a2 3b [2] b9 3d [2] a5 3a [2] b9 15 }

  condition:
    any of them
}