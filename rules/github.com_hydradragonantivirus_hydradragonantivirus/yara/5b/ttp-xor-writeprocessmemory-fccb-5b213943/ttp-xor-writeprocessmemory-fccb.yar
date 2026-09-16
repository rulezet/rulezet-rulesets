rule TTP_XOR_WriteProcessMemory_fccb {
  strings:
    $key_fccb = { ab b9 [2] 99 9b [2] 9f ae [2] b1 ae [2] 8e b2 }

  condition:
    any of them
}