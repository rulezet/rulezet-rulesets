rule TTP_XOR_WriteProcessMemory_ba1a {
  strings:
    $key_ba1a = { ed 68 [2] df 4a [2] d9 7f [2] f7 7f [2] c8 63 }

  condition:
    any of them
}