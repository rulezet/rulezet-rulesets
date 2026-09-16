rule TTP_XOR_WriteProcessMemory_bae3 {
  strings:
    $key_bae3 = { ed 91 [2] df b3 [2] d9 86 [2] f7 86 [2] c8 9a }

  condition:
    any of them
}