rule TTP_XOR_WriteProcessMemory_0915 {
  strings:
    $key_0915 = { 5e 67 [2] 6c 45 [2] 6a 70 [2] 44 70 [2] 7b 6c }

  condition:
    any of them
}