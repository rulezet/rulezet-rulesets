rule TTP_XOR_WriteProcessMemory_3fef {
  strings:
    $key_3fef = { 68 9d [2] 5a bf [2] 5c 8a [2] 72 8a [2] 4d 96 }

  condition:
    any of them
}