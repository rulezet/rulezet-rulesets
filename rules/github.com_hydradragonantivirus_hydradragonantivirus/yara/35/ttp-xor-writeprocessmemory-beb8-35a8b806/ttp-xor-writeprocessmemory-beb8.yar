rule TTP_XOR_WriteProcessMemory_beb8 {
  strings:
    $key_beb8 = { e9 ca [2] db e8 [2] dd dd [2] f3 dd [2] cc c1 }

  condition:
    any of them
}