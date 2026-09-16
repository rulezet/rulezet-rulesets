rule TTP_XOR_WriteProcessMemory_868e {
  strings:
    $key_868e = { d1 fc [2] e3 de [2] e5 eb [2] cb eb [2] f4 f7 }

  condition:
    any of them
}