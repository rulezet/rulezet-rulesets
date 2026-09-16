rule TTP_XOR_WriteProcessMemory_1c3c {
  strings:
    $key_1c3c = { 4b 4e [2] 79 6c [2] 7f 59 [2] 51 59 [2] 6e 45 }

  condition:
    any of them
}