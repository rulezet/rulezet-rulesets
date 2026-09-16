rule TTP_XOR_WriteProcessMemory_dbfd {
  strings:
    $key_dbfd = { 8c 8f [2] be ad [2] b8 98 [2] 96 98 [2] a9 84 }

  condition:
    any of them
}