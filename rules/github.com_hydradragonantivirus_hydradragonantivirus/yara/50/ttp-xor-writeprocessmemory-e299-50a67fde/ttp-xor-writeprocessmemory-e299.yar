rule TTP_XOR_WriteProcessMemory_e299 {
  strings:
    $key_e299 = { b5 eb [2] 87 c9 [2] 81 fc [2] af fc [2] 90 e0 }

  condition:
    any of them
}