rule TTP_XOR_WriteProcessMemory_4ee4 {
  strings:
    $key_4ee4 = { 19 96 [2] 2b b4 [2] 2d 81 [2] 03 81 [2] 3c 9d }

  condition:
    any of them
}