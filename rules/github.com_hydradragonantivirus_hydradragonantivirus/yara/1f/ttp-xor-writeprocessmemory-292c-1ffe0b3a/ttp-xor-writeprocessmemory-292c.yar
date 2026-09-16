rule TTP_XOR_WriteProcessMemory_292c {
  strings:
    $key_292c = { 7e 5e [2] 4c 7c [2] 4a 49 [2] 64 49 [2] 5b 55 }

  condition:
    any of them
}