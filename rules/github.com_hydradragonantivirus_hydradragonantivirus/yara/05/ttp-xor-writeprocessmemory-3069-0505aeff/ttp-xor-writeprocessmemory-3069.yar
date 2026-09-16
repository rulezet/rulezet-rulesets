rule TTP_XOR_WriteProcessMemory_3069 {
  strings:
    $key_3069 = { 67 1b [2] 55 39 [2] 53 0c [2] 7d 0c [2] 42 10 }

  condition:
    any of them
}