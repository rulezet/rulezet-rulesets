rule TTP_XOR_WriteProcessMemory_2bbe {
  strings:
    $key_2bbe = { 7c cc [2] 4e ee [2] 48 db [2] 66 db [2] 59 c7 }

  condition:
    any of them
}