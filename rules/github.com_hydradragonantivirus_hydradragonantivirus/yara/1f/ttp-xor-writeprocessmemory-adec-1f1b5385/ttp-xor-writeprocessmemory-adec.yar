rule TTP_XOR_WriteProcessMemory_adec {
  strings:
    $key_adec = { fa 9e [2] c8 bc [2] ce 89 [2] e0 89 [2] df 95 }

  condition:
    any of them
}