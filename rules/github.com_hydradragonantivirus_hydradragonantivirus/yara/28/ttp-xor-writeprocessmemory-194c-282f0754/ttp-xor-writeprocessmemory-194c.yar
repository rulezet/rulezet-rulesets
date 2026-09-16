rule TTP_XOR_WriteProcessMemory_194c {
  strings:
    $key_194c = { 4e 3e [2] 7c 1c [2] 7a 29 [2] 54 29 [2] 6b 35 }

  condition:
    any of them
}