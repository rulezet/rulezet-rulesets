rule TTP_XOR_WriteProcessMemory_faea {
  strings:
    $key_faea = { ad 98 [2] 9f ba [2] 99 8f [2] b7 8f [2] 88 93 }

  condition:
    any of them
}