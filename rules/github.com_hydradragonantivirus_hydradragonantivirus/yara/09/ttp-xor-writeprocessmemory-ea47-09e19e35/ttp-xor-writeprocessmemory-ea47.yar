rule TTP_XOR_WriteProcessMemory_ea47 {
  strings:
    $key_ea47 = { bd 35 [2] 8f 17 [2] 89 22 [2] a7 22 [2] 98 3e }

  condition:
    any of them
}