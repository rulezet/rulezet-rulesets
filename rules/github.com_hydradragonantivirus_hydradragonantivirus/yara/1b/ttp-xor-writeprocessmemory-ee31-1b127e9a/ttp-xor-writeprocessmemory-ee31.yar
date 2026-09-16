rule TTP_XOR_WriteProcessMemory_ee31 {
  strings:
    $key_ee31 = { b9 43 [2] 8b 61 [2] 8d 54 [2] a3 54 [2] 9c 48 }

  condition:
    any of them
}