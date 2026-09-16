rule TTP_XOR_QUAD_CurrentVersionRun_24f7 {
  strings:
    $key_24f7 = { 77 98 [2] 53 96 [2] 78 ba [2] 56 98 [2] 42 83 [2] 4d 99 [2] 53 84 [2] 51 85 [2] 4a 83 [2] 56 84 [2] 4a ab }

  condition:
    any of them
}