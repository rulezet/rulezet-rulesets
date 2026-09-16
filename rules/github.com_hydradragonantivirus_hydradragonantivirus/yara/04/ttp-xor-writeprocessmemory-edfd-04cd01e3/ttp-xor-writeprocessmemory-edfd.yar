rule TTP_XOR_WriteProcessMemory_edfd {
  strings:
    $key_edfd = { ba 8f [2] 88 ad [2] 8e 98 [2] a0 98 [2] 9f 84 }

  condition:
    any of them
}