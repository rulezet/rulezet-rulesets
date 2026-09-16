rule TTP_XOR_WriteProcessMemory_5a57 {
  strings:
    $key_5a57 = { 0d 25 [2] 3f 07 [2] 39 32 [2] 17 32 [2] 28 2e }

  condition:
    any of them
}