rule TTP_XOR_WriteProcessMemory_690c {
  strings:
    $key_690c = { 3e 7e [2] 0c 5c [2] 0a 69 [2] 24 69 [2] 1b 75 }

  condition:
    any of them
}