rule TTP_XOR_WriteProcessMemory_3101 {
  strings:
    $key_3101 = { 66 73 [2] 54 51 [2] 52 64 [2] 7c 64 [2] 43 78 }

  condition:
    any of them
}