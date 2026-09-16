rule TTP_XOR_WriteProcessMemory_2b5c {
  strings:
    $key_2b5c = { 7c 2e [2] 4e 0c [2] 48 39 [2] 66 39 [2] 59 25 }

  condition:
    any of them
}