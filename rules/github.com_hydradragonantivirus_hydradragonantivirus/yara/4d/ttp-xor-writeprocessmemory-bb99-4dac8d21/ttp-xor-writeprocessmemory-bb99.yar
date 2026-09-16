rule TTP_XOR_WriteProcessMemory_bb99 {
  strings:
    $key_bb99 = { ec eb [2] de c9 [2] d8 fc [2] f6 fc [2] c9 e0 }

  condition:
    any of them
}