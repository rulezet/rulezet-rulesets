rule TTP_XOR_WriteProcessMemory_dfbd {
  strings:
    $key_dfbd = { 88 cf [2] ba ed [2] bc d8 [2] 92 d8 [2] ad c4 }

  condition:
    any of them
}