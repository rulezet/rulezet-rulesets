rule TTP_XOR_WriteProcessMemory_ee24 {
  strings:
    $key_ee24 = { b9 56 [2] 8b 74 [2] 8d 41 [2] a3 41 [2] 9c 5d }

  condition:
    any of them
}