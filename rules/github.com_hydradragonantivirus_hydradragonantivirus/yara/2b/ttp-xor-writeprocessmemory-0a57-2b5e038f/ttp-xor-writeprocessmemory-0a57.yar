rule TTP_XOR_WriteProcessMemory_0a57 {
  strings:
    $key_0a57 = { 5d 25 [2] 6f 07 [2] 69 32 [2] 47 32 [2] 78 2e }

  condition:
    any of them
}