rule TTP_XOR_QUAD_CurrentVersionRun_f306 {
  strings:
    $key_f306 = { a0 69 [2] 84 67 [2] af 4b [2] 81 69 [2] 95 72 [2] 9a 68 [2] 84 75 [2] 86 74 [2] 9d 72 [2] 81 75 [2] 9d 5a }

  condition:
    any of them
}