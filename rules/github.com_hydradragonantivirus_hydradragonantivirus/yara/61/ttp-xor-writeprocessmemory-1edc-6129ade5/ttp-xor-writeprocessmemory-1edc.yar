rule TTP_XOR_WriteProcessMemory_1edc {
  strings:
    $key_1edc = { 49 ae [2] 7b 8c [2] 7d b9 [2] 53 b9 [2] 6c a5 }

  condition:
    any of them
}