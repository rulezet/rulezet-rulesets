rule TTP_XOR_WriteProcessMemory_6a57 {
  strings:
    $key_6a57 = { 3d 25 [2] 0f 07 [2] 09 32 [2] 27 32 [2] 18 2e }

  condition:
    any of them
}