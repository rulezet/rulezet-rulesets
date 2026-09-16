rule TTP_XOR_WriteProcessMemory_3f39 {
  strings:
    $key_3f39 = { 68 4b [2] 5a 69 [2] 5c 5c [2] 72 5c [2] 4d 40 }

  condition:
    any of them
}