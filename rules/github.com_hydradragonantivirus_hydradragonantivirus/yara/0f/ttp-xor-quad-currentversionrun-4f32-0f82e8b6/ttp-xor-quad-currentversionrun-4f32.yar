rule TTP_XOR_QUAD_CurrentVersionRun_4f32 {
  strings:
    $key_4f32 = { 1c 5d [2] 38 53 [2] 13 7f [2] 3d 5d [2] 29 46 [2] 26 5c [2] 38 41 [2] 3a 40 [2] 21 46 [2] 3d 41 [2] 21 6e }

  condition:
    any of them
}