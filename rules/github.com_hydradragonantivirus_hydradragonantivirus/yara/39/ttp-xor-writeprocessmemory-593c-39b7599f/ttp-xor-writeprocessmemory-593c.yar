rule TTP_XOR_WriteProcessMemory_593c {
  strings:
    $key_593c = { 0e 4e [2] 3c 6c [2] 3a 59 [2] 14 59 [2] 2b 45 }

  condition:
    any of them
}