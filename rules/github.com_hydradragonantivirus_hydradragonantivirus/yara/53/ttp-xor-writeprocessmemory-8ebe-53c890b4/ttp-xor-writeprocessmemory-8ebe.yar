rule TTP_XOR_WriteProcessMemory_8ebe {
  strings:
    $key_8ebe = { d9 cc [2] eb ee [2] ed db [2] c3 db [2] fc c7 }

  condition:
    any of them
}