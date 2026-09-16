rule TTP_XOR_WriteProcessMemory_33d7 {
  strings:
    $key_33d7 = { 64 a5 [2] 56 87 [2] 50 b2 [2] 7e b2 [2] 41 ae }

  condition:
    any of them
}