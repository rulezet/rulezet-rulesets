rule TTP_XOR_WriteProcessMemory_bb09 {
  strings:
    $key_bb09 = { ec 7b [2] de 59 [2] d8 6c [2] f6 6c [2] c9 70 }

  condition:
    any of them
}