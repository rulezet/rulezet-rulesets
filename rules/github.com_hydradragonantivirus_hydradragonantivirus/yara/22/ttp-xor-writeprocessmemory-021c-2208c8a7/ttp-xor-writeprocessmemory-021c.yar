rule TTP_XOR_WriteProcessMemory_021c {
  strings:
    $key_021c = { 55 6e [2] 67 4c [2] 61 79 [2] 4f 79 [2] 70 65 }

  condition:
    any of them
}