rule TTP_XOR_WriteProcessMemory_341c {
  strings:
    $key_341c = { 63 6e [2] 51 4c [2] 57 79 [2] 79 79 [2] 46 65 }

  condition:
    any of them
}