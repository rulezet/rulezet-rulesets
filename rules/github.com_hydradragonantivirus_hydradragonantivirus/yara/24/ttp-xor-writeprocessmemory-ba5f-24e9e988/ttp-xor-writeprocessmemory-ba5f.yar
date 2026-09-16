rule TTP_XOR_WriteProcessMemory_ba5f {
  strings:
    $key_ba5f = { ed 2d [2] df 0f [2] d9 3a [2] f7 3a [2] c8 26 }

  condition:
    any of them
}