rule TTP_XOR_WriteProcessMemory_005c {
  strings:
    $key_005c = { 57 2e [2] 65 0c [2] 63 39 [2] 4d 39 [2] 72 25 }

  condition:
    any of them
}