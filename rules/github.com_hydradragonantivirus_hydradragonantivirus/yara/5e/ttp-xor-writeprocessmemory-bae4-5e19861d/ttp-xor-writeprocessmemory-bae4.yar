rule TTP_XOR_WriteProcessMemory_bae4 {
  strings:
    $key_bae4 = { ed 96 [2] df b4 [2] d9 81 [2] f7 81 [2] c8 9d }

  condition:
    any of them
}