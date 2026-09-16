rule TTP_XOR_WriteProcessMemory_b8b8 {
  strings:
    $key_b8b8 = { ef ca [2] dd e8 [2] db dd [2] f5 dd [2] ca c1 }

  condition:
    any of them
}