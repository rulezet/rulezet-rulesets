rule TTP_XOR_WriteProcessMemory_320c {
  strings:
    $key_320c = { 65 7e [2] 57 5c [2] 51 69 [2] 7f 69 [2] 40 75 }

  condition:
    any of them
}