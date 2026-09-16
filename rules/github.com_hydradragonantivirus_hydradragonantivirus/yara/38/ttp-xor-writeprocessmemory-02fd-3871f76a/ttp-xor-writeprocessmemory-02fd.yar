rule TTP_XOR_WriteProcessMemory_02fd {
  strings:
    $key_02fd = { 55 8f [2] 67 ad [2] 61 98 [2] 4f 98 [2] 70 84 }

  condition:
    any of them
}