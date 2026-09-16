rule TTP_XOR_QUAD_CurrentVersionRun_34f7 {
  strings:
    $key_34f7 = { 67 98 [2] 43 96 [2] 68 ba [2] 46 98 [2] 52 83 [2] 5d 99 [2] 43 84 [2] 41 85 [2] 5a 83 [2] 46 84 [2] 5a ab }

  condition:
    any of them
}