rule TTP_XOR_WriteProcessMemory_e499 {
  strings:
    $key_e499 = { b3 eb [2] 81 c9 [2] 87 fc [2] a9 fc [2] 96 e0 }

  condition:
    any of them
}