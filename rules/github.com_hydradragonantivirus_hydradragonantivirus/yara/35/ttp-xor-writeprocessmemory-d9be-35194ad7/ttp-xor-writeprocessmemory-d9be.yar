rule TTP_XOR_WriteProcessMemory_d9be {
  strings:
    $key_d9be = { 8e cc [2] bc ee [2] ba db [2] 94 db [2] ab c7 }

  condition:
    any of them
}