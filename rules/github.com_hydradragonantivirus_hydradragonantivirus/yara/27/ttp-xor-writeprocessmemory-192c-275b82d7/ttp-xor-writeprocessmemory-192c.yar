rule TTP_XOR_WriteProcessMemory_192c {
  strings:
    $key_192c = { 4e 5e [2] 7c 7c [2] 7a 49 [2] 54 49 [2] 6b 55 }

  condition:
    any of them
}