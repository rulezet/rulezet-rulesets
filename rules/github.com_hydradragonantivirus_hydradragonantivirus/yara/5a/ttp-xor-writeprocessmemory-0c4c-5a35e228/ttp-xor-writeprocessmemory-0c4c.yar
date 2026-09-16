rule TTP_XOR_WriteProcessMemory_0c4c {
  strings:
    $key_0c4c = { 5b 3e [2] 69 1c [2] 6f 29 [2] 41 29 [2] 7e 35 }

  condition:
    any of them
}