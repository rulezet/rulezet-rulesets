rule TTP_XOR_WriteProcessMemory_90dc {
  strings:
    $key_90dc = { c7 ae [2] f5 8c [2] f3 b9 [2] dd b9 [2] e2 a5 }

  condition:
    any of them
}