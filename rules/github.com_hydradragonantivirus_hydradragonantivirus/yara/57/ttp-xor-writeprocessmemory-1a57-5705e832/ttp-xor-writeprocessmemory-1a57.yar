rule TTP_XOR_WriteProcessMemory_1a57 {
  strings:
    $key_1a57 = { 4d 25 [2] 7f 07 [2] 79 32 [2] 57 32 [2] 68 2e }

  condition:
    any of them
}