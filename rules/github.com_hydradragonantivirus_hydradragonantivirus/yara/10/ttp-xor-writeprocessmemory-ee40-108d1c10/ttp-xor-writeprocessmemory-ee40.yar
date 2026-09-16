rule TTP_XOR_WriteProcessMemory_ee40 {
  strings:
    $key_ee40 = { b9 32 [2] 8b 10 [2] 8d 25 [2] a3 25 [2] 9c 39 }

  condition:
    any of them
}