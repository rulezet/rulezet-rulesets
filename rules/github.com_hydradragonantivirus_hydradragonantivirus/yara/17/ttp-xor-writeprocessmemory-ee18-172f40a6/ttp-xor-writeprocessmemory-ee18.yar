rule TTP_XOR_WriteProcessMemory_ee18 {
  strings:
    $key_ee18 = { b9 6a [2] 8b 48 [2] 8d 7d [2] a3 7d [2] 9c 61 }

  condition:
    any of them
}