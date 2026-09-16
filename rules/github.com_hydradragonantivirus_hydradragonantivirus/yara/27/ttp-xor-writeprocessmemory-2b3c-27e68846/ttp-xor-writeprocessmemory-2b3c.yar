rule TTP_XOR_WriteProcessMemory_2b3c {
  strings:
    $key_2b3c = { 7c 4e [2] 4e 6c [2] 48 59 [2] 66 59 [2] 59 45 }

  condition:
    any of them
}