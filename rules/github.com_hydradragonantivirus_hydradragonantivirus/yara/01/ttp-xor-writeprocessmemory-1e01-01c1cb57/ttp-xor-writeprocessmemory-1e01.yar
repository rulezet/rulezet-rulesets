rule TTP_XOR_WriteProcessMemory_1e01 {
  strings:
    $key_1e01 = { 49 73 [2] 7b 51 [2] 7d 64 [2] 53 64 [2] 6c 78 }

  condition:
    any of them
}