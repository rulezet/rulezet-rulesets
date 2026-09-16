rule TTP_XOR_WriteProcessMemory_caea {
  strings:
    $key_caea = { 9d 98 [2] af ba [2] a9 8f [2] 87 8f [2] b8 93 }

  condition:
    any of them
}