rule TTP_XOR_WriteProcessMemory_135c {
  strings:
    $key_135c = { 44 2e [2] 76 0c [2] 70 39 [2] 5e 39 [2] 61 25 }

  condition:
    any of them
}