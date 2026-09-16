rule TTP_XOR_WriteProcessMemory_7a67 {
  strings:
    $key_7a67 = { 2d 15 [2] 1f 37 [2] 19 02 [2] 37 02 [2] 08 1e }

  condition:
    any of them
}