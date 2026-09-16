rule TTP_XOR_WriteProcessMemory_8423 {
  strings:
    $key_8423 = { d3 51 [2] e1 73 [2] e7 46 [2] c9 46 [2] f6 5a }

  condition:
    any of them
}