rule TTP_XOR_WriteProcessMemory_e989 {
  strings:
    $key_e989 = { be fb [2] 8c d9 [2] 8a ec [2] a4 ec [2] 9b f0 }

  condition:
    any of them
}