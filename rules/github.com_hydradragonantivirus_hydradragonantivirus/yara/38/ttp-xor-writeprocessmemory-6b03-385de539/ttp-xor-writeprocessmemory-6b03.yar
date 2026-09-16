rule TTP_XOR_WriteProcessMemory_6b03 {
  strings:
    $key_6b03 = { 3c 71 [2] 0e 53 [2] 08 66 [2] 26 66 [2] 19 7a }

  condition:
    any of them
}