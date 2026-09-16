rule TTP_XOR_WriteProcessMemory_113c {
  strings:
    $key_113c = { 46 4e [2] 74 6c [2] 72 59 [2] 5c 59 [2] 63 45 }

  condition:
    any of them
}