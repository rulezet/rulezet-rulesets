rule TTP_XOR_WriteProcessMemory_abe9 {
  strings:
    $key_abe9 = { fc 9b [2] ce b9 [2] c8 8c [2] e6 8c [2] d9 90 }

  condition:
    any of them
}