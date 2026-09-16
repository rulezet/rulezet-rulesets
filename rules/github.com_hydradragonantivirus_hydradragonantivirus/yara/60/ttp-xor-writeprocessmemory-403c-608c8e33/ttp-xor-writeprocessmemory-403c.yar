rule TTP_XOR_WriteProcessMemory_403c {
  strings:
    $key_403c = { 17 4e [2] 25 6c [2] 23 59 [2] 0d 59 [2] 32 45 }

  condition:
    any of them
}