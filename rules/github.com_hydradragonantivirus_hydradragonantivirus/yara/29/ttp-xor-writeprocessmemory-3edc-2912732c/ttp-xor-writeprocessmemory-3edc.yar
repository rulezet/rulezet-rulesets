rule TTP_XOR_WriteProcessMemory_3edc {
  strings:
    $key_3edc = { 69 ae [2] 5b 8c [2] 5d b9 [2] 73 b9 [2] 4c a5 }

  condition:
    any of them
}