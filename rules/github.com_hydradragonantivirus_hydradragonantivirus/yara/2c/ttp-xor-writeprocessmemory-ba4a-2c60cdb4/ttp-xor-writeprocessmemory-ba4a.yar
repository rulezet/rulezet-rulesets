rule TTP_XOR_WriteProcessMemory_ba4a {
  strings:
    $key_ba4a = { ed 38 [2] df 1a [2] d9 2f [2] f7 2f [2] c8 33 }

  condition:
    any of them
}