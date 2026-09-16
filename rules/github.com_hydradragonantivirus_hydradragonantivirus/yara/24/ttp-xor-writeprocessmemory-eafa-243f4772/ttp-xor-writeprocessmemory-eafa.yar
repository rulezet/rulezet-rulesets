rule TTP_XOR_WriteProcessMemory_eafa {
  strings:
    $key_eafa = { bd 88 [2] 8f aa [2] 89 9f [2] a7 9f [2] 98 83 }

  condition:
    any of them
}