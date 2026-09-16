rule TTP_XOR_WriteProcessMemory_6c3c {
  strings:
    $key_6c3c = { 3b 4e [2] 09 6c [2] 0f 59 [2] 21 59 [2] 1e 45 }

  condition:
    any of them
}