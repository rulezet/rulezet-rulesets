rule TTP_XOR_WriteProcessMemory_f4fd {
  strings:
    $key_f4fd = { a3 8f [2] 91 ad [2] 97 98 [2] b9 98 [2] 86 84 }

  condition:
    any of them
}