rule TTP_XOR_WriteProcessMemory_0401 {
  strings:
    $key_0401 = { 53 73 [2] 61 51 [2] 67 64 [2] 49 64 [2] 76 78 }

  condition:
    any of them
}