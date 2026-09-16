rule TTP_XOR_WriteProcessMemory_0a03 {
  strings:
    $key_0a03 = { 5d 71 [2] 6f 53 [2] 69 66 [2] 47 66 [2] 78 7a }

  condition:
    any of them
}