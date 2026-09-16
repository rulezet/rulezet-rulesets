rule TTP_XOR_WriteProcessMemory_ee87 {
  strings:
    $key_ee87 = { b9 f5 [2] 8b d7 [2] 8d e2 [2] a3 e2 [2] 9c fe }

  condition:
    any of them
}