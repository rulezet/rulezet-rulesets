rule TTP_XOR_QUAD_CurrentVersionRun_f32b {
  strings:
    $key_f32b = { a0 44 [2] 84 4a [2] af 66 [2] 81 44 [2] 95 5f [2] 9a 45 [2] 84 58 [2] 86 59 [2] 9d 5f [2] 81 58 [2] 9d 77 }

  condition:
    any of them
}