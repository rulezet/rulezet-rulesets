rule TTP_XOR_WriteProcessMemory_ba2a {
  strings:
    $key_ba2a = { ed 58 [2] df 7a [2] d9 4f [2] f7 4f [2] c8 53 }

  condition:
    any of them
}