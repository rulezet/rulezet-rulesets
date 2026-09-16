rule TTP_XOR_WriteProcessMemory_5afe {
  strings:
    $key_5afe = { 0d 8c [2] 3f ae [2] 39 9b [2] 17 9b [2] 28 87 }

  condition:
    any of them
}