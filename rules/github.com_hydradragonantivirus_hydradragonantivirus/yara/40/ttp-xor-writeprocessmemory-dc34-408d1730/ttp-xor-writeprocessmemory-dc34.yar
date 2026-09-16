rule TTP_XOR_WriteProcessMemory_dc34 {
  strings:
    $key_dc34 = { 8b 46 [2] b9 64 [2] bf 51 [2] 91 51 [2] ae 4d }

  condition:
    any of them
}