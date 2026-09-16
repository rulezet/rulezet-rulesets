rule TTP_XOR_WriteProcessMemory_0acb {
  strings:
    $key_0acb = { 5d b9 [2] 6f 9b [2] 69 ae [2] 47 ae [2] 78 b2 }

  condition:
    any of them
}