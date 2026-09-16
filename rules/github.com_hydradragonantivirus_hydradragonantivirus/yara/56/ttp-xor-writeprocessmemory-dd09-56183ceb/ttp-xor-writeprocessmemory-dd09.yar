rule TTP_XOR_WriteProcessMemory_dd09 {
  strings:
    $key_dd09 = { 8a 7b [2] b8 59 [2] be 6c [2] 90 6c [2] af 70 }

  condition:
    any of them
}