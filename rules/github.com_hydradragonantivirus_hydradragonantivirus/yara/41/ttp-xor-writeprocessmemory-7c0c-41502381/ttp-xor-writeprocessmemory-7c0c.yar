rule TTP_XOR_WriteProcessMemory_7c0c {
  strings:
    $key_7c0c = { 2b 7e [2] 19 5c [2] 1f 69 [2] 31 69 [2] 0e 75 }

  condition:
    any of them
}