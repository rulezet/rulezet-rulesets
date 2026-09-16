rule TTP_XOR_WriteProcessMemory_1659 {
  strings:
    $key_1659 = { 41 2b [2] 73 09 [2] 75 3c [2] 5b 3c [2] 64 20 }

  condition:
    any of them
}