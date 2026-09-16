rule TTP_XOR_WriteProcessMemory_be88 {
  strings:
    $key_be88 = { e9 fa [2] db d8 [2] dd ed [2] f3 ed [2] cc f1 }

  condition:
    any of them
}