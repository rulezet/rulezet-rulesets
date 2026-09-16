rule TTP_XOR_WriteProcessMemory_04f1 {
  strings:
    $key_04f1 = { 53 83 [2] 61 a1 [2] 67 94 [2] 49 94 [2] 76 88 }

  condition:
    any of them
}