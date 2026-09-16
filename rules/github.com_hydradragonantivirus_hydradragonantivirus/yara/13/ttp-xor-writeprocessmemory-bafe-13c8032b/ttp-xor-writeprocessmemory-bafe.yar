rule TTP_XOR_WriteProcessMemory_bafe {
  strings:
    $key_bafe = { ed 8c [2] df ae [2] d9 9b [2] f7 9b [2] c8 87 }

  condition:
    any of them
}