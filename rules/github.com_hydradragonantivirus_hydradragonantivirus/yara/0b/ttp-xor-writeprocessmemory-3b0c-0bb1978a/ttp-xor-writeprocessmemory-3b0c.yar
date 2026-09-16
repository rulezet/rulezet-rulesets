rule TTP_XOR_WriteProcessMemory_3b0c {
  strings:
    $key_3b0c = { 6c 7e [2] 5e 5c [2] 58 69 [2] 76 69 [2] 49 75 }

  condition:
    any of them
}