rule TTP_XOR_WriteProcessMemory_2bcb {
  strings:
    $key_2bcb = { 7c b9 [2] 4e 9b [2] 48 ae [2] 66 ae [2] 59 b2 }

  condition:
    any of them
}