rule TTP_XOR_WriteProcessMemory_dcbe {
  strings:
    $key_dcbe = { 8b cc [2] b9 ee [2] bf db [2] 91 db [2] ae c7 }

  condition:
    any of them
}