rule TTP_XOR_WriteProcessMemory_dd37 {
  strings:
    $key_dd37 = { 8a 45 [2] b8 67 [2] be 52 [2] 90 52 [2] af 4e }

  condition:
    any of them
}