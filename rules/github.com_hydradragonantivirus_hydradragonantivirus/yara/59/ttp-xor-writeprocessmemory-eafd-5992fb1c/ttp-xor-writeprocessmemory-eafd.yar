rule TTP_XOR_WriteProcessMemory_eafd {
  strings:
    $key_eafd = { bd 8f [2] 8f ad [2] 89 98 [2] a7 98 [2] 98 84 }

  condition:
    any of them
}