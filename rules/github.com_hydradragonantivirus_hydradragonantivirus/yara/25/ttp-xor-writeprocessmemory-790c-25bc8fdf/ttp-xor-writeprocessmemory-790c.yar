rule TTP_XOR_WriteProcessMemory_790c {
  strings:
    $key_790c = { 2e 7e [2] 1c 5c [2] 1a 69 [2] 34 69 [2] 0b 75 }

  condition:
    any of them
}