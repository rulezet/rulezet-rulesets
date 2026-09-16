rule TTP_XOR_WriteProcessMemory_ee67 {
  strings:
    $key_ee67 = { b9 15 [2] 8b 37 [2] 8d 02 [2] a3 02 [2] 9c 1e }

  condition:
    any of them
}