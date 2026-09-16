rule TTP_XOR_WriteProcessMemory_e3ac {
  strings:
    $key_e3ac = { b4 de [2] 86 fc [2] 80 c9 [2] ae c9 [2] 91 d5 }

  condition:
    any of them
}