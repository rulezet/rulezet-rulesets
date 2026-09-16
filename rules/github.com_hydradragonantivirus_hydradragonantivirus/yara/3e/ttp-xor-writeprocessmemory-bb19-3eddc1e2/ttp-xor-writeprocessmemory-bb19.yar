rule TTP_XOR_WriteProcessMemory_bb19 {
  strings:
    $key_bb19 = { ec 6b [2] de 49 [2] d8 7c [2] f6 7c [2] c9 60 }

  condition:
    any of them
}