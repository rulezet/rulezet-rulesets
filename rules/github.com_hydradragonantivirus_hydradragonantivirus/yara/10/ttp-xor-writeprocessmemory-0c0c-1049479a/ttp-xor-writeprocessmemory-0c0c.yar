rule TTP_XOR_WriteProcessMemory_0c0c {
  strings:
    $key_0c0c = { 5b 7e [2] 69 5c [2] 6f 69 [2] 41 69 [2] 7e 75 }

  condition:
    any of them
}