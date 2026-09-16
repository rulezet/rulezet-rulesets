rule TTP_XOR_WriteProcessMemory_8fcd {
  strings:
    $key_8fcd = { d8 bf [2] ea 9d [2] ec a8 [2] c2 a8 [2] fd b4 }

  condition:
    any of them
}