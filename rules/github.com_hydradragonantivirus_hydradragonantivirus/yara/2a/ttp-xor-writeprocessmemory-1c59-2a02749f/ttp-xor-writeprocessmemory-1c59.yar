rule TTP_XOR_WriteProcessMemory_1c59 {
  strings:
    $key_1c59 = { 4b 2b [2] 79 09 [2] 7f 3c [2] 51 3c [2] 6e 20 }

  condition:
    any of them
}