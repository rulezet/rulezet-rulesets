rule TTP_XOR_WriteProcessMemory_0a11 {
  strings:
    $key_0a11 = { 5d 63 [2] 6f 41 [2] 69 74 [2] 47 74 [2] 78 68 }

  condition:
    any of them
}