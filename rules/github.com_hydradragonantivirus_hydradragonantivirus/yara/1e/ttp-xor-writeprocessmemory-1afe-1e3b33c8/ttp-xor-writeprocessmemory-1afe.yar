rule TTP_XOR_WriteProcessMemory_1afe {
  strings:
    $key_1afe = { 4d 8c [2] 7f ae [2] 79 9b [2] 57 9b [2] 68 87 }

  condition:
    any of them
}