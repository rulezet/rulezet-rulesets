rule TTP_XOR_WriteProcessMemory_bbfd {
  strings:
    $key_bbfd = { ec 8f [2] de ad [2] d8 98 [2] f6 98 [2] c9 84 }

  condition:
    any of them
}