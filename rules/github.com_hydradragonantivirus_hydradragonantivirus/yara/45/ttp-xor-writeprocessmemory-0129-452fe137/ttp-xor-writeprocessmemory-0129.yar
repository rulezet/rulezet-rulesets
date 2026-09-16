rule TTP_XOR_WriteProcessMemory_0129 {
  strings:
    $key_0129 = { 56 5b [2] 64 79 [2] 62 4c [2] 4c 4c [2] 73 50 }

  condition:
    any of them
}