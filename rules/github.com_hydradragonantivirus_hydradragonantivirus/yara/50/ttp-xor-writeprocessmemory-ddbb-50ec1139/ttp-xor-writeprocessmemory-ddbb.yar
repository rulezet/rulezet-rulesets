rule TTP_XOR_WriteProcessMemory_ddbb {
  strings:
    $key_ddbb = { 8a c9 [2] b8 eb [2] be de [2] 90 de [2] af c2 }

  condition:
    any of them
}