rule TTP_XOR_QUAD_CurrentVersionRun_f1f7 {
  strings:
    $key_f1f7 = { a2 98 [2] 86 96 [2] ad ba [2] 83 98 [2] 97 83 [2] 98 99 [2] 86 84 [2] 84 85 [2] 9f 83 [2] 83 84 [2] 9f ab }

  condition:
    any of them
}