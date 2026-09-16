rule TTP_XOR_QUAD_CurrentVersionRun_6f32 {
  strings:
    $key_6f32 = { 3c 5d [2] 18 53 [2] 33 7f [2] 1d 5d [2] 09 46 [2] 06 5c [2] 18 41 [2] 1a 40 [2] 01 46 [2] 1d 41 [2] 01 6e }

  condition:
    any of them
}