rule TTP_XOR_WriteProcessMemory_2a39 {
  strings:
    $key_2a39 = { 7d 4b [2] 4f 69 [2] 49 5c [2] 67 5c [2] 58 40 }

  condition:
    any of them
}