rule TTP_XOR_WriteProcessMemory_ee36 {
  strings:
    $key_ee36 = { b9 44 [2] 8b 66 [2] 8d 53 [2] a3 53 [2] 9c 4f }

  condition:
    any of them
}