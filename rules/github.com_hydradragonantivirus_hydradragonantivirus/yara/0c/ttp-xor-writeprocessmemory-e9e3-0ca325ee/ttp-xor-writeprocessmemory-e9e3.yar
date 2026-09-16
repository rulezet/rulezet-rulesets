rule TTP_XOR_WriteProcessMemory_e9e3 {
  strings:
    $key_e9e3 = { be 91 [2] 8c b3 [2] 8a 86 [2] a4 86 [2] 9b 9a }

  condition:
    any of them
}