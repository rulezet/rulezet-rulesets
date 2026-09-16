rule TTP_XOR_WriteProcessMemory_dd19 {
  strings:
    $key_dd19 = { 8a 6b [2] b8 49 [2] be 7c [2] 90 7c [2] af 60 }

  condition:
    any of them
}