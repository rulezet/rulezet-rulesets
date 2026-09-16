rule TTP_XOR_WriteProcessMemory_1bfe {
  strings:
    $key_1bfe = { 4c 8c [2] 7e ae [2] 78 9b [2] 56 9b [2] 69 87 }

  condition:
    any of them
}