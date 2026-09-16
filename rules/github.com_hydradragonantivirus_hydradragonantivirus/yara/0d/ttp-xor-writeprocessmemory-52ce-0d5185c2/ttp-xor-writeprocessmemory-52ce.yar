rule TTP_XOR_WriteProcessMemory_52ce {
  strings:
    $key_52ce = { 05 bc [2] 37 9e [2] 31 ab [2] 1f ab [2] 20 b7 }

  condition:
    any of them
}