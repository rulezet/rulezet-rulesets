rule TTP_XOR_WriteProcessMemory_6c5c {
  strings:
    $key_6c5c = { 3b 2e [2] 09 0c [2] 0f 39 [2] 21 39 [2] 1e 25 }

  condition:
    any of them
}