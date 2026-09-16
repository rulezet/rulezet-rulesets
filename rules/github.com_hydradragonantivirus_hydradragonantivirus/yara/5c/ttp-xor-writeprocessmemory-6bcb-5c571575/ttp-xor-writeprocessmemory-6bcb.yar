rule TTP_XOR_WriteProcessMemory_6bcb {
  strings:
    $key_6bcb = { 3c b9 [2] 0e 9b [2] 08 ae [2] 26 ae [2] 19 b2 }

  condition:
    any of them
}