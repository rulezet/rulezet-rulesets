rule TTP_XOR_WriteProcessMemory_ee33 {
  strings:
    $key_ee33 = { b9 41 [2] 8b 63 [2] 8d 56 [2] a3 56 [2] 9c 4a }

  condition:
    any of them
}