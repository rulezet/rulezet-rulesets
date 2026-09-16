rule TTP_XOR_WriteProcessMemory_795c {
  strings:
    $key_795c = { 2e 2e [2] 1c 0c [2] 1a 39 [2] 34 39 [2] 0b 25 }

  condition:
    any of them
}