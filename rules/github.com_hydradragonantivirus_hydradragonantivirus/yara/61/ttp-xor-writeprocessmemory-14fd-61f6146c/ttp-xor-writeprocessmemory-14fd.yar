rule TTP_XOR_WriteProcessMemory_14fd {
  strings:
    $key_14fd = { 43 8f [2] 71 ad [2] 77 98 [2] 59 98 [2] 66 84 }

  condition:
    any of them
}