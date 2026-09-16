rule TTP_XOR_WriteProcessMemory_86be {
  strings:
    $key_86be = { d1 cc [2] e3 ee [2] e5 db [2] cb db [2] f4 c7 }

  condition:
    any of them
}