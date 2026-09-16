rule TTP_XOR_WriteProcessMemory_092b {
  strings:
    $key_092b = { 5e 59 [2] 6c 7b [2] 6a 4e [2] 44 4e [2] 7b 52 }

  condition:
    any of them
}