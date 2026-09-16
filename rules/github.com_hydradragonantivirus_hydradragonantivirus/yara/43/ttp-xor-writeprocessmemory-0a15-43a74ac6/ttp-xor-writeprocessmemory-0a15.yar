rule TTP_XOR_WriteProcessMemory_0a15 {
  strings:
    $key_0a15 = { 5d 67 [2] 6f 45 [2] 69 70 [2] 47 70 [2] 78 6c }

  condition:
    any of them
}