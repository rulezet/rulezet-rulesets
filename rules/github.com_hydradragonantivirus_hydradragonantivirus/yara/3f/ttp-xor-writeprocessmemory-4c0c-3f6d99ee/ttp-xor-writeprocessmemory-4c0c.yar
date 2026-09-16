rule TTP_XOR_WriteProcessMemory_4c0c {
  strings:
    $key_4c0c = { 1b 7e [2] 29 5c [2] 2f 69 [2] 01 69 [2] 3e 75 }

  condition:
    any of them
}