rule TTP_XOR_WriteProcessMemory_cbfd {
  strings:
    $key_cbfd = { 9c 8f [2] ae ad [2] a8 98 [2] 86 98 [2] b9 84 }

  condition:
    any of them
}