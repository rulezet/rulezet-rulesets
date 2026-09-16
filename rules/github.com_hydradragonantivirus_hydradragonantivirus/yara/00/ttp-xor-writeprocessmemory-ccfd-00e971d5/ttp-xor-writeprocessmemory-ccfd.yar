rule TTP_XOR_WriteProcessMemory_ccfd {
  strings:
    $key_ccfd = { 9b 8f [2] a9 ad [2] af 98 [2] 81 98 [2] be 84 }

  condition:
    any of them
}