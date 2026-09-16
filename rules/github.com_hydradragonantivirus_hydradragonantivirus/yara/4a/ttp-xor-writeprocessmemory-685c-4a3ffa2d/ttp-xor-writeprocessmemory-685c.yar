rule TTP_XOR_WriteProcessMemory_685c {
  strings:
    $key_685c = { 3f 2e [2] 0d 0c [2] 0b 39 [2] 25 39 [2] 1a 25 }

  condition:
    any of them
}