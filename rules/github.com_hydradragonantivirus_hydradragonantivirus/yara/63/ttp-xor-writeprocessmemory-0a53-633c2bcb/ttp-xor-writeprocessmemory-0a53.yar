rule TTP_XOR_WriteProcessMemory_0a53 {
  strings:
    $key_0a53 = { 5d 21 [2] 6f 03 [2] 69 36 [2] 47 36 [2] 78 2a }

  condition:
    any of them
}