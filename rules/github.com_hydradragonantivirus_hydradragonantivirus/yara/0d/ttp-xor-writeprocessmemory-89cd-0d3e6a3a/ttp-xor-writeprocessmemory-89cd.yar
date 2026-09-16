rule TTP_XOR_WriteProcessMemory_89cd {
  strings:
    $key_89cd = { de bf [2] ec 9d [2] ea a8 [2] c4 a8 [2] fb b4 }

  condition:
    any of them
}