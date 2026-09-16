rule TTP_XOR_QUAD_CurrentVersionRun_3f32 {
  strings:
    $key_3f32 = { 6c 5d [2] 48 53 [2] 63 7f [2] 4d 5d [2] 59 46 [2] 56 5c [2] 48 41 [2] 4a 40 [2] 51 46 [2] 4d 41 [2] 51 6e }

  condition:
    any of them
}