rule TTP_XOR_WriteProcessMemory_ba6f {
  strings:
    $key_ba6f = { ed 1d [2] df 3f [2] d9 0a [2] f7 0a [2] c8 16 }

  condition:
    any of them
}