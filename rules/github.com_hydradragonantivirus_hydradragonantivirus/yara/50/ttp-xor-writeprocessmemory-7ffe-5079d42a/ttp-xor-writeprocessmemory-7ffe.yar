rule TTP_XOR_WriteProcessMemory_7ffe {
  strings:
    $key_7ffe = { 28 8c [2] 1a ae [2] 1c 9b [2] 32 9b [2] 0d 87 }

  condition:
    any of them
}