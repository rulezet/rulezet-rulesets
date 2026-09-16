rule TTP_XOR_WriteProcessMemory_3bbe {
  strings:
    $key_3bbe = { 6c cc [2] 5e ee [2] 58 db [2] 76 db [2] 49 c7 }

  condition:
    any of them
}