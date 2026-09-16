rule TTP_XOR_WriteProcessMemory_388d {
  strings:
    $key_388d = { 6f ff [2] 5d dd [2] 5b e8 [2] 75 e8 [2] 4a f4 }

  condition:
    any of them
}