rule TTP_XOR_WriteProcessMemory_021e {
  strings:
    $key_021e = { 55 6c [2] 67 4e [2] 61 7b [2] 4f 7b [2] 70 67 }

  condition:
    any of them
}