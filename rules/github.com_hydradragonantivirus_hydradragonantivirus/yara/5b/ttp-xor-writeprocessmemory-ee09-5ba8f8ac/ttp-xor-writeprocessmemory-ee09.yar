rule TTP_XOR_WriteProcessMemory_ee09 {
  strings:
    $key_ee09 = { b9 7b [2] 8b 59 [2] 8d 6c [2] a3 6c [2] 9c 70 }

  condition:
    any of them
}