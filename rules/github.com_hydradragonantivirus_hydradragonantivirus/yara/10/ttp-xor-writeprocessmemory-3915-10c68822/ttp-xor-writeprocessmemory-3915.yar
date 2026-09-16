rule TTP_XOR_WriteProcessMemory_3915 {
  strings:
    $key_3915 = { 6e 67 [2] 5c 45 [2] 5a 70 [2] 74 70 [2] 4b 6c }

  condition:
    any of them
}