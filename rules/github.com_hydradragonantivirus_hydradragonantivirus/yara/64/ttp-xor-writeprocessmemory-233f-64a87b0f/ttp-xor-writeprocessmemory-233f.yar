rule TTP_XOR_WriteProcessMemory_233f {
  strings:
    $key_233f = { 74 4d [2] 46 6f [2] 40 5a [2] 6e 5a [2] 51 46 }

  condition:
    any of them
}