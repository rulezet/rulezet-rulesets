rule TTP_XOR_WriteProcessMemory_7f69 {
  strings:
    $key_7f69 = { 28 1b [2] 1a 39 [2] 1c 0c [2] 32 0c [2] 0d 10 }

  condition:
    any of them
}