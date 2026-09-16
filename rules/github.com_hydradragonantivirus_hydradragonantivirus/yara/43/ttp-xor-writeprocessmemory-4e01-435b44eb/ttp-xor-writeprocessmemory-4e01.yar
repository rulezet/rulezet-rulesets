rule TTP_XOR_WriteProcessMemory_4e01 {
  strings:
    $key_4e01 = { 19 73 [2] 2b 51 [2] 2d 64 [2] 03 64 [2] 3c 78 }

  condition:
    any of them
}