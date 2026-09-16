rule TTP_XOR_WriteProcessMemory_6e87 {
  strings:
    $key_6e87 = { 39 f5 [2] 0b d7 [2] 0d e2 [2] 23 e2 [2] 1c fe }

  condition:
    any of them
}