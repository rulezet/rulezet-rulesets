rule TTP_XOR_QUAD_CurrentVersionRun_f3d2 {
  strings:
    $key_f3d2 = { a0 bd [2] 84 b3 [2] af 9f [2] 81 bd [2] 95 a6 [2] 9a bc [2] 84 a1 [2] 86 a0 [2] 9d a6 [2] 81 a1 [2] 9d 8e }

  condition:
    any of them
}