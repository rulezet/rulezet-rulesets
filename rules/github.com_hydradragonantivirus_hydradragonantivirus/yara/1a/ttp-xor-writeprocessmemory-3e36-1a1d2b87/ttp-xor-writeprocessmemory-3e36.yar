rule TTP_XOR_WriteProcessMemory_3e36 {
  strings:
    $key_3e36 = { 69 44 [2] 5b 66 [2] 5d 53 [2] 73 53 [2] 4c 4f }

  condition:
    any of them
}