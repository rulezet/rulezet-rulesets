rule TTP_XOR_WriteProcessMemory_9904 {
  strings:
    $key_9904 = { ce 76 [2] fc 54 [2] fa 61 [2] d4 61 [2] eb 7d }

  condition:
    any of them
}