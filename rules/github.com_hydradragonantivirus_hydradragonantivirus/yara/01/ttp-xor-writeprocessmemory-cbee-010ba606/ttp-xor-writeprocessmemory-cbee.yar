rule TTP_XOR_WriteProcessMemory_cbee {
  strings:
    $key_cbee = { 9c 9c [2] ae be [2] a8 8b [2] 86 8b [2] b9 97 }

  condition:
    any of them
}