rule TTP_XOR_WriteProcessMemory_2b1c {
  strings:
    $key_2b1c = { 7c 6e [2] 4e 4c [2] 48 79 [2] 66 79 [2] 59 65 }

  condition:
    any of them
}