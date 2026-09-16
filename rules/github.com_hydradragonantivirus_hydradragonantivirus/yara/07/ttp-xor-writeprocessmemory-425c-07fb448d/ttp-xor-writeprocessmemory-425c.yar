rule TTP_XOR_WriteProcessMemory_425c {
  strings:
    $key_425c = { 15 2e [2] 27 0c [2] 21 39 [2] 0f 39 [2] 30 25 }

  condition:
    any of them
}