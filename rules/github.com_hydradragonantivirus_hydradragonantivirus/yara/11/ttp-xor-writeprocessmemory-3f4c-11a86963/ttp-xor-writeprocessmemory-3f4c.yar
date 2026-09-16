rule TTP_XOR_WriteProcessMemory_3f4c {
  strings:
    $key_3f4c = { 68 3e [2] 5a 1c [2] 5c 29 [2] 72 29 [2] 4d 35 }

  condition:
    any of them
}