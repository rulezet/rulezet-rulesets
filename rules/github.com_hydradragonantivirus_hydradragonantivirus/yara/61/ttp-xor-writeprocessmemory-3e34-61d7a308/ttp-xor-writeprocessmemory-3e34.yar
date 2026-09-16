rule TTP_XOR_WriteProcessMemory_3e34 {
  strings:
    $key_3e34 = { 69 46 [2] 5b 64 [2] 5d 51 [2] 73 51 [2] 4c 4d }

  condition:
    any of them
}