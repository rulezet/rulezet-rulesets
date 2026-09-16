rule TTP_XOR_WriteProcessMemory_3e14 {
  strings:
    $key_3e14 = { 69 66 [2] 5b 44 [2] 5d 71 [2] 73 71 [2] 4c 6d }

  condition:
    any of them
}