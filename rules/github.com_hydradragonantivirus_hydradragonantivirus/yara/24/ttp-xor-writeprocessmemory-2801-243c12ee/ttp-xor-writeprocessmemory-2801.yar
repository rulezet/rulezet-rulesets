rule TTP_XOR_WriteProcessMemory_2801 {
  strings:
    $key_2801 = { 7f 73 [2] 4d 51 [2] 4b 64 [2] 65 64 [2] 5a 78 }

  condition:
    any of them
}