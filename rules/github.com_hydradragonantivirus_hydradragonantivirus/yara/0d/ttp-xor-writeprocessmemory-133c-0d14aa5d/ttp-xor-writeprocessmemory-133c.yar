rule TTP_XOR_WriteProcessMemory_133c {
  strings:
    $key_133c = { 44 4e [2] 76 6c [2] 70 59 [2] 5e 59 [2] 61 45 }

  condition:
    any of them
}