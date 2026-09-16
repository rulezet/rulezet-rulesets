rule TTP_XOR_WriteProcessMemory_ba7a {
  strings:
    $key_ba7a = { ed 08 [2] df 2a [2] d9 1f [2] f7 1f [2] c8 03 }

  condition:
    any of them
}