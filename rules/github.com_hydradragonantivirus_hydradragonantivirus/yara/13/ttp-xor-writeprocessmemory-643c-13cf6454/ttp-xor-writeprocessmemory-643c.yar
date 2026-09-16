rule TTP_XOR_WriteProcessMemory_643c {
  strings:
    $key_643c = { 33 4e [2] 01 6c [2] 07 59 [2] 29 59 [2] 16 45 }

  condition:
    any of them
}