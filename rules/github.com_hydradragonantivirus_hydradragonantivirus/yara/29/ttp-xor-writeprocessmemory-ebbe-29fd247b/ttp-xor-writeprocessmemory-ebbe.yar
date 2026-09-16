rule TTP_XOR_WriteProcessMemory_ebbe {
  strings:
    $key_ebbe = { bc cc [2] 8e ee [2] 88 db [2] a6 db [2] 99 c7 }

  condition:
    any of them
}