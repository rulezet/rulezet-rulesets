rule TTP_XOR_WriteProcessMemory_ec99 {
  strings:
    $key_ec99 = { bb eb [2] 89 c9 [2] 8f fc [2] a1 fc [2] 9e e0 }

  condition:
    any of them
}