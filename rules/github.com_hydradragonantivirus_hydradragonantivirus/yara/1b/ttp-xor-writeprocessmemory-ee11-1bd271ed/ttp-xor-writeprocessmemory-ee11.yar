rule TTP_XOR_WriteProcessMemory_ee11 {
  strings:
    $key_ee11 = { b9 63 [2] 8b 41 [2] 8d 74 [2] a3 74 [2] 9c 68 }

  condition:
    any of them
}