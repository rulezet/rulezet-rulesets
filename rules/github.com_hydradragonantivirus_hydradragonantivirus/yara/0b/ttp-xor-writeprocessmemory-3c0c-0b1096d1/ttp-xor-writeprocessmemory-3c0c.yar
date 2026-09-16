rule TTP_XOR_WriteProcessMemory_3c0c {
  strings:
    $key_3c0c = { 6b 7e [2] 59 5c [2] 5f 69 [2] 71 69 [2] 4e 75 }

  condition:
    any of them
}