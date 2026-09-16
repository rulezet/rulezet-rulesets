rule TTP_XOR_WriteProcessMemory_baee {
  strings:
    $key_baee = { ed 9c [2] df be [2] d9 8b [2] f7 8b [2] c8 97 }

  condition:
    any of them
}