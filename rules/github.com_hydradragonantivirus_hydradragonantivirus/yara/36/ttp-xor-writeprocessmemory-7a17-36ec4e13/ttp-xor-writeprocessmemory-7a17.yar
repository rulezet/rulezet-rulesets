rule TTP_XOR_WriteProcessMemory_7a17 {
  strings:
    $key_7a17 = { 2d 65 [2] 1f 47 [2] 19 72 [2] 37 72 [2] 08 6e }

  condition:
    any of them
}