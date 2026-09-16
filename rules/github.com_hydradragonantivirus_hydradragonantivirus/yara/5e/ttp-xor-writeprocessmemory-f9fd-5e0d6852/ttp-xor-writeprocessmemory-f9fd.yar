rule TTP_XOR_WriteProcessMemory_f9fd {
  strings:
    $key_f9fd = { ae 8f [2] 9c ad [2] 9a 98 [2] b4 98 [2] 8b 84 }

  condition:
    any of them
}