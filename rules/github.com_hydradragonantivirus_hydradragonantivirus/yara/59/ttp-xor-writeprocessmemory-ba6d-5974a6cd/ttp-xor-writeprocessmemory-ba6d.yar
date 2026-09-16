rule TTP_XOR_WriteProcessMemory_ba6d {
  strings:
    $key_ba6d = { ed 1f [2] df 3d [2] d9 08 [2] f7 08 [2] c8 14 }

  condition:
    any of them
}