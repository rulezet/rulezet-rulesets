rule TTP_XOR_WriteProcessMemory_6ec7 {
  strings:
    $key_6ec7 = { 39 b5 [2] 0b 97 [2] 0d a2 [2] 23 a2 [2] 1c be }

  condition:
    any of them
}