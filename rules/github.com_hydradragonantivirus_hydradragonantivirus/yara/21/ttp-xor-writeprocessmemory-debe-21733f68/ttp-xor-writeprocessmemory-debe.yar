rule TTP_XOR_WriteProcessMemory_debe {
  strings:
    $key_debe = { 89 cc [2] bb ee [2] bd db [2] 93 db [2] ac c7 }

  condition:
    any of them
}