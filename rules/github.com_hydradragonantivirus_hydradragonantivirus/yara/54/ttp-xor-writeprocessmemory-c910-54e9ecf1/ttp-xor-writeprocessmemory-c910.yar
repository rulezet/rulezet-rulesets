rule TTP_XOR_WriteProcessMemory_c910 {
  strings:
    $key_c910 = { 9e 62 [2] ac 40 [2] aa 75 [2] 84 75 [2] bb 69 }

  condition:
    any of them
}