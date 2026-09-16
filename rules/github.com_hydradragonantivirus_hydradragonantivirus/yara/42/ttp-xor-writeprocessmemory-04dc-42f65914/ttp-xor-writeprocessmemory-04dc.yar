rule TTP_XOR_WriteProcessMemory_04dc {
  strings:
    $key_04dc = { 53 ae [2] 61 8c [2] 67 b9 [2] 49 b9 [2] 76 a5 }

  condition:
    any of them
}