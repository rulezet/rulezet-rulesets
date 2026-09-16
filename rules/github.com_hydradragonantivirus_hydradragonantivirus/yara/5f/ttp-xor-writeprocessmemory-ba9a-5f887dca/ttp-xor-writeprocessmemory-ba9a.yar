rule TTP_XOR_WriteProcessMemory_ba9a {
  strings:
    $key_ba9a = { ed e8 [2] df ca [2] d9 ff [2] f7 ff [2] c8 e3 }

  condition:
    any of them
}