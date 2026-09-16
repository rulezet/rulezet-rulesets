rule TTP_XOR_WriteProcessMemory_ee46 {
  strings:
    $key_ee46 = { b9 34 [2] 8b 16 [2] 8d 23 [2] a3 23 [2] 9c 3f }

  condition:
    any of them
}