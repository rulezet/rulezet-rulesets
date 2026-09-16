rule TTP_XOR_WriteProcessMemory_cafd {
  strings:
    $key_cafd = { 9d 8f [2] af ad [2] a9 98 [2] 87 98 [2] b8 84 }

  condition:
    any of them
}