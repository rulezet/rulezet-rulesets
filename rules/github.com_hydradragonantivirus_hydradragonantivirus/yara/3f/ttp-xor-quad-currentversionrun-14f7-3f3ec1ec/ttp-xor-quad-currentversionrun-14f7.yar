rule TTP_XOR_QUAD_CurrentVersionRun_14f7 {
  strings:
    $key_14f7 = { 47 98 [2] 63 96 [2] 48 ba [2] 66 98 [2] 72 83 [2] 7d 99 [2] 63 84 [2] 61 85 [2] 7a 83 [2] 66 84 [2] 7a ab }

  condition:
    any of them
}