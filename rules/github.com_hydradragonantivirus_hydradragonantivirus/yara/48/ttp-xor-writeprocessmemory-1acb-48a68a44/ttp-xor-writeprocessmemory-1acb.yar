rule TTP_XOR_WriteProcessMemory_1acb {
  strings:
    $key_1acb = { 4d b9 [2] 7f 9b [2] 79 ae [2] 57 ae [2] 68 b2 }

  condition:
    any of them
}