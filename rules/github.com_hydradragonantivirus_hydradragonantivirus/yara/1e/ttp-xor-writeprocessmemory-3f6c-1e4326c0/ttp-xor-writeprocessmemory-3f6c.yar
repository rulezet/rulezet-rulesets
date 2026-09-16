rule TTP_XOR_WriteProcessMemory_3f6c {
  strings:
    $key_3f6c = { 68 1e [2] 5a 3c [2] 5c 09 [2] 72 09 [2] 4d 15 }

  condition:
    any of them
}