rule TTP_XOR_WriteProcessMemory_2edc {
  strings:
    $key_2edc = { 79 ae [2] 4b 8c [2] 4d b9 [2] 63 b9 [2] 5c a5 }

  condition:
    any of them
}