rule TTP_XOR_WriteProcessMemory_d9bd {
  strings:
    $key_d9bd = { 8e cf [2] bc ed [2] ba d8 [2] 94 d8 [2] ab c4 }

  condition:
    any of them
}