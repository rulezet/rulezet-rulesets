rule TTP_XOR_WriteProcessMemory_2a57 {
  strings:
    $key_2a57 = { 7d 25 [2] 4f 07 [2] 49 32 [2] 67 32 [2] 58 2e }

  condition:
    any of them
}