rule TTP_XOR_WriteProcessMemory_413c {
  strings:
    $key_413c = { 16 4e [2] 24 6c [2] 22 59 [2] 0c 59 [2] 33 45 }

  condition:
    any of them
}