rule TTP_XOR_WriteProcessMemory_dd3c {
  strings:
    $key_dd3c = { 8a 4e [2] b8 6c [2] be 59 [2] 90 59 [2] af 45 }

  condition:
    any of them
}