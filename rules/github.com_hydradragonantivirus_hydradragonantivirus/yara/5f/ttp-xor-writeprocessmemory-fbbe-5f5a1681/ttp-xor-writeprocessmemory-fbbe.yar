rule TTP_XOR_WriteProcessMemory_fbbe {
  strings:
    $key_fbbe = { ac cc [2] 9e ee [2] 98 db [2] b6 db [2] 89 c7 }

  condition:
    any of them
}