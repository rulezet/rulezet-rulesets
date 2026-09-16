rule TTP_XOR_WriteProcessMemory_62f9 {
  strings:
    $key_62f9 = { 35 8b [2] 07 a9 [2] 01 9c [2] 2f 9c [2] 10 80 }

  condition:
    any of them
}