rule TTP_XOR_WriteProcessMemory_cbbe {
  strings:
    $key_cbbe = { 9c cc [2] ae ee [2] a8 db [2] 86 db [2] b9 c7 }

  condition:
    any of them
}