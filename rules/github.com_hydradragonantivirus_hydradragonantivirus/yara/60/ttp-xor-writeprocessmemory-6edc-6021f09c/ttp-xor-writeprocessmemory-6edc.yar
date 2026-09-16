rule TTP_XOR_WriteProcessMemory_6edc {
  strings:
    $key_6edc = { 39 ae [2] 0b 8c [2] 0d b9 [2] 23 b9 [2] 1c a5 }

  condition:
    any of them
}