rule TTP_XOR_WriteProcessMemory_e799 {
  strings:
    $key_e799 = { b0 eb [2] 82 c9 [2] 84 fc [2] aa fc [2] 95 e0 }

  condition:
    any of them
}