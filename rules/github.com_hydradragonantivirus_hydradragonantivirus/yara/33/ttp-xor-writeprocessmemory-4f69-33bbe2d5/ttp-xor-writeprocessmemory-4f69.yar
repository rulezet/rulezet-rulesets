rule TTP_XOR_WriteProcessMemory_4f69 {
  strings:
    $key_4f69 = { 18 1b [2] 2a 39 [2] 2c 0c [2] 02 0c [2] 3d 10 }

  condition:
    any of them
}