rule TTP_XOR_WriteProcessMemory_e98b {
  strings:
    $key_e98b = { be f9 [2] 8c db [2] 8a ee [2] a4 ee [2] 9b f2 }

  condition:
    any of them
}