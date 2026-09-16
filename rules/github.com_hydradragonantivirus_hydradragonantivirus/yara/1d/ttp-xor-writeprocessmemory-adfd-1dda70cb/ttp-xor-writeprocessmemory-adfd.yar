rule TTP_XOR_WriteProcessMemory_adfd {
  strings:
    $key_adfd = { fa 8f [2] c8 ad [2] ce 98 [2] e0 98 [2] df 84 }

  condition:
    any of them
}