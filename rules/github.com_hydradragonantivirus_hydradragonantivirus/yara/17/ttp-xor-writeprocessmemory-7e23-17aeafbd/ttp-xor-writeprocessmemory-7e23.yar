rule TTP_XOR_WriteProcessMemory_7e23 {
  strings:
    $key_7e23 = { 29 51 [2] 1b 73 [2] 1d 46 [2] 33 46 [2] 0c 5a }

  condition:
    any of them
}