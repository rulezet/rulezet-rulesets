rule TTP_XOR_WriteProcessMemory_8ccb {
  strings:
    $key_8ccb = { db b9 [2] e9 9b [2] ef ae [2] c1 ae [2] fe b2 }

  condition:
    any of them
}