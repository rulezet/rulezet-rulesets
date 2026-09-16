rule TTP_XOR_WriteProcessMemory_8fdf {
  strings:
    $key_8fdf = { d8 ad [2] ea 8f [2] ec ba [2] c2 ba [2] fd a6 }

  condition:
    any of them
}