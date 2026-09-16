rule TTP_XOR_WriteProcessMemory_efdc {
  strings:
    $key_efdc = { b8 ae [2] 8a 8c [2] 8c b9 [2] a2 b9 [2] 9d a5 }

  condition:
    any of them
}