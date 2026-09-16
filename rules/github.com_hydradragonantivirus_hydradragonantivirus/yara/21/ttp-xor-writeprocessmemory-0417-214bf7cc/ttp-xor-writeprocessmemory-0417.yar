rule TTP_XOR_WriteProcessMemory_0417 {
  strings:
    $key_0417 = { 53 65 [2] 61 47 [2] 67 72 [2] 49 72 [2] 76 6e }

  condition:
    any of them
}