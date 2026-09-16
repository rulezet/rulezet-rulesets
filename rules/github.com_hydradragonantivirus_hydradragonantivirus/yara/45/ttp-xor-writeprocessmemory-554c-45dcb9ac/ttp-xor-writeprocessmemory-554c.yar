rule TTP_XOR_WriteProcessMemory_554c {
  strings:
    $key_554c = { 02 3e [2] 30 1c [2] 36 29 [2] 18 29 [2] 27 35 }

  condition:
    any of them
}