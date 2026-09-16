rule TTP_XOR_WriteProcessMemory_3e03 {
  strings:
    $key_3e03 = { 69 71 [2] 5b 53 [2] 5d 66 [2] 73 66 [2] 4c 7a }

  condition:
    any of them
}