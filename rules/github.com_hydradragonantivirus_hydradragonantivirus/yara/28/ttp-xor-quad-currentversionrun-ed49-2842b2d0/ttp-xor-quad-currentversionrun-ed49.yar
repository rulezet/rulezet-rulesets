rule TTP_XOR_QUAD_CurrentVersionRun_ed49 {
  strings:
    $key_ed49 = { be 26 [2] 9a 28 [2] b1 04 [2] 9f 26 [2] 8b 3d [2] 84 27 [2] 9a 3a [2] 98 3b [2] 83 3d [2] 9f 3a [2] 83 15 }

  condition:
    any of them
}