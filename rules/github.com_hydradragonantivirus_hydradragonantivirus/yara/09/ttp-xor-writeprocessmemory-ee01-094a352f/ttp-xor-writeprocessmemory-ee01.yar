rule TTP_XOR_WriteProcessMemory_ee01 {
  strings:
    $key_ee01 = { b9 73 [2] 8b 51 [2] 8d 64 [2] a3 64 [2] 9c 78 }

  condition:
    any of them
}