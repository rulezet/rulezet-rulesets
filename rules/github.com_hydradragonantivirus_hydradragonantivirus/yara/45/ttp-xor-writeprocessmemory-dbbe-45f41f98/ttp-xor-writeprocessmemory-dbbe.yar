rule TTP_XOR_WriteProcessMemory_dbbe {
  strings:
    $key_dbbe = { 8c cc [2] be ee [2] b8 db [2] 96 db [2] a9 c7 }

  condition:
    any of them
}