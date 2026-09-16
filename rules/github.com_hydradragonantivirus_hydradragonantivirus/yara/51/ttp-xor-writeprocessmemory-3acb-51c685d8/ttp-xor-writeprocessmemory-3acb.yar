rule TTP_XOR_WriteProcessMemory_3acb {
  strings:
    $key_3acb = { 6d b9 [2] 5f 9b [2] 59 ae [2] 77 ae [2] 48 b2 }

  condition:
    any of them
}