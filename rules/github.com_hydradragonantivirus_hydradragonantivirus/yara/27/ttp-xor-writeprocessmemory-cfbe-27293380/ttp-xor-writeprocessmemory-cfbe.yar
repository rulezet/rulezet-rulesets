rule TTP_XOR_WriteProcessMemory_cfbe {
  strings:
    $key_cfbe = { 98 cc [2] aa ee [2] ac db [2] 82 db [2] bd c7 }

  condition:
    any of them
}