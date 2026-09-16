rule TTP_XOR_WriteProcessMemory_4511 {
  strings:
    $key_4511 = { 12 63 [2] 20 41 [2] 26 74 [2] 08 74 [2] 37 68 }

  condition:
    any of them
}