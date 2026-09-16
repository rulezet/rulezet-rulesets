rule TTP_XOR_WriteProcessMemory_dd39 {
  strings:
    $key_dd39 = { 8a 4b [2] b8 69 [2] be 5c [2] 90 5c [2] af 40 }

  condition:
    any of them
}