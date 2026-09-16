rule TTP_XOR_WriteProcessMemory_195c {
  strings:
    $key_195c = { 4e 2e [2] 7c 0c [2] 7a 39 [2] 54 39 [2] 6b 25 }

  condition:
    any of them
}