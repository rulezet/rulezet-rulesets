rule TTP_XOR_WriteProcessMemory_995c {
  strings:
    $key_995c = { ce 2e [2] fc 0c [2] fa 39 [2] d4 39 [2] eb 25 }

  condition:
    any of them
}