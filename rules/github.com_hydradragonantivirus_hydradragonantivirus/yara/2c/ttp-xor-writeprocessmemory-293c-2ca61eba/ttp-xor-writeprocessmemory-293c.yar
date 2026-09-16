rule TTP_XOR_WriteProcessMemory_293c {
  strings:
    $key_293c = { 7e 4e [2] 4c 6c [2] 4a 59 [2] 64 59 [2] 5b 45 }

  condition:
    any of them
}