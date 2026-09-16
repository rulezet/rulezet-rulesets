rule TTP_XOR_WriteProcessMemory_bb8e {
  strings:
    $key_bb8e = { ec fc [2] de de [2] d8 eb [2] f6 eb [2] c9 f7 }

  condition:
    any of them
}