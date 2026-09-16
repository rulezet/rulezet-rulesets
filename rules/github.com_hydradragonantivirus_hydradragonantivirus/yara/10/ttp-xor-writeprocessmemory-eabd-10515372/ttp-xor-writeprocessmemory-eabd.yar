rule TTP_XOR_WriteProcessMemory_eabd {
  strings:
    $key_eabd = { bd cf [2] 8f ed [2] 89 d8 [2] a7 d8 [2] 98 c4 }

  condition:
    any of them
}