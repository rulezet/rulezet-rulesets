rule TTP_XOR_WriteProcessMemory_04e9 {
  strings:
    $key_04e9 = { 53 9b [2] 61 b9 [2] 67 8c [2] 49 8c [2] 76 90 }

  condition:
    any of them
}