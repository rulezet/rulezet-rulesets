rule TTP_XOR_WriteProcessMemory_5bbe {
  strings:
    $key_5bbe = { 0c cc [2] 3e ee [2] 38 db [2] 16 db [2] 29 c7 }

  condition:
    any of them
}