rule TTP_XOR_WriteProcessMemory_0069 {
  strings:
    $key_0069 = { 57 1b [2] 65 39 [2] 63 0c [2] 4d 0c [2] 72 10 }

  condition:
    any of them
}