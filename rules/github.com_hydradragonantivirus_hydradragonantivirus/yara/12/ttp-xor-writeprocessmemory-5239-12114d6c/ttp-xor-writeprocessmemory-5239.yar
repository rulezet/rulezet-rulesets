rule TTP_XOR_WriteProcessMemory_5239 {
  strings:
    $key_5239 = { 05 4b [2] 37 69 [2] 31 5c [2] 1f 5c [2] 20 40 }

  condition:
    any of them
}