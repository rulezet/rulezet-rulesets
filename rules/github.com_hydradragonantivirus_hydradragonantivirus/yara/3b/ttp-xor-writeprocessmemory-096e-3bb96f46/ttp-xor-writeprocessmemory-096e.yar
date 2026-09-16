rule TTP_XOR_WriteProcessMemory_096e {
  strings:
    $key_096e = { 5e 1c [2] 6c 3e [2] 6a 0b [2] 44 0b [2] 7b 17 }

  condition:
    any of them
}