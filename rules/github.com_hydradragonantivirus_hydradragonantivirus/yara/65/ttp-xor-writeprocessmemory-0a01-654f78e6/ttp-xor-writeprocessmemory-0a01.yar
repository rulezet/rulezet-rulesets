rule TTP_XOR_WriteProcessMemory_0a01 {
  strings:
    $key_0a01 = { 5d 73 [2] 6f 51 [2] 69 64 [2] 47 64 [2] 78 78 }

  condition:
    any of them
}