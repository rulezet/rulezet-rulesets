rule TTP_XOR_WriteProcessMemory_280c {
  strings:
    $key_280c = { 7f 7e [2] 4d 5c [2] 4b 69 [2] 65 69 [2] 5a 75 }

  condition:
    any of them
}