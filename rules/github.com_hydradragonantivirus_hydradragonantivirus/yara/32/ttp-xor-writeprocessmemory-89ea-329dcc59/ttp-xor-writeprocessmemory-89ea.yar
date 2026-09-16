rule TTP_XOR_WriteProcessMemory_89ea {
  strings:
    $key_89ea = { de 98 [2] ec ba [2] ea 8f [2] c4 8f [2] fb 93 }

  condition:
    any of them
}