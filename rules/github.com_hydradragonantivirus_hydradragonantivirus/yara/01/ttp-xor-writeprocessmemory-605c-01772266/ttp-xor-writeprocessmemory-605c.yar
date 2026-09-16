rule TTP_XOR_WriteProcessMemory_605c {
  strings:
    $key_605c = { 37 2e [2] 05 0c [2] 03 39 [2] 2d 39 [2] 12 25 }

  condition:
    any of them
}